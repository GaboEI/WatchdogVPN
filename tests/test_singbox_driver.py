from __future__ import annotations

import json
import subprocess
import unittest
from unittest.mock import patch

from app_policy.models import AppPolicy, AppPolicyRule
from config.lan_sharing import LANGatewayRuntimeConfig, LANProxyRuntimeConfig
from dns.models import DNSChannel, DNSChannelName, DNSPolicy, DNSRule, Resolver
from drivers.base import ManagementPathSafetyError
from drivers.singbox_driver import SingBoxDriver
from drivers.runtime_paths import OwnedProcess, TCPListenerObservation
from models.profile import Profile, ProfileSource, ProtocolType
from parsers.wg_config import parse_wg_config
from route_chains.runtime import (
    ChainDNSPathStatus,
    ChainHopRuntimeStatus,
    ChainRuntimeHopPlan,
    ChainRuntimePlan,
    ChainRuntimeStatus,
)
from rules.models import Rule, RuleGroup


class SingBoxDriverBinaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.driver = SingBoxDriver()

    @patch("drivers.singbox_driver.shutil.which", return_value="/usr/bin/sing-box")
    @patch("drivers.singbox_driver.os.path.exists", return_value=False)
    @patch("drivers.singbox_driver.os.access", return_value=False)
    def test_find_binary_falls_back_to_which(self, access_mock, exists_mock, which_mock) -> None:
        self.assertEqual(self.driver.find_singbox_binary(), "/usr/bin/sing-box")

    @patch.dict("drivers.singbox_driver.os.environ", {"WATCHDOGVPN_SINGBOX_BIN": "/opt/watchdogvpn/sing-box"})
    @patch("drivers.singbox_driver.os.path.exists", return_value=True)
    @patch("drivers.singbox_driver.os.access", return_value=True)
    def test_find_binary_accepts_env_override_for_compatible_cores(self, access_mock, exists_mock) -> None:
        self.assertEqual(self.driver.find_singbox_binary(), "/opt/watchdogvpn/sing-box")

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
    def test_generated_proxy_inbounds_are_loopback_only(self, bind_mock, write_mock) -> None:
        profile = self._profile(
            ProtocolType.VLESS,
            host="vless.example.com",
            port=443,
            uuid="uuid-1",
        )

        config = self.driver.generate_singbox_config(profile)
        proxy_inbounds = {
            inbound["tag"]: inbound
            for inbound in config["inbounds"]
            if inbound["tag"] in {"watchdogvpn-socks-in", "watchdogvpn-http-in"}
        }

        self.assertEqual(
            proxy_inbounds,
            {
                "watchdogvpn-socks-in": {
                    "type": "socks",
                    "tag": "watchdogvpn-socks-in",
                    "listen": "127.0.0.1",
                    "listen_port": 2080,
                },
                "watchdogvpn-http-in": {
                    "type": "http",
                    "tag": "watchdogvpn-http-in",
                    "listen": "127.0.0.1",
                    "listen_port": 2081,
                },
            },
        )
        self.assertFalse(
            any(inbound.get("listen") in {"0.0.0.0", "::"} for inbound in config["inbounds"])
        )

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    def test_generate_singbox_config_uses_warning_log_level_by_default(
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

        config = self.driver.generate_singbox_config(profile)

        self.assertEqual(config["log"], {"level": "warning"})

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    @patch.dict("drivers.singbox_driver.os.environ", {"WATCHDOGVPN_SINGBOX_LOG_LEVEL": "debug"})
    def test_generate_singbox_config_accepts_bounded_debug_log_level(
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

        config = self.driver.generate_singbox_config(profile)

        self.assertEqual(config["log"], {"level": "debug"})

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    @patch.dict("drivers.singbox_driver.os.environ", {"WATCHDOGVPN_SINGBOX_LOG_LEVEL": "verbose"})
    def test_generate_singbox_config_rejects_unknown_log_level(
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

        config = self.driver.generate_singbox_config(profile)

        self.assertEqual(config["log"], {"level": "warning"})

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    def test_lan_proxy_adds_authenticated_inbounds_and_preserves_loopback(
        self, bind_mock, write_mock
    ) -> None:
        profile = self._profile(
            ProtocolType.VLESS,
            host="vless.example.com",
            port=443,
            uuid="uuid-1",
        )
        lan_proxy = LANProxyRuntimeConfig(
            bind_address="192.168.0.228",
            socks_port=2080,
            http_port=2081,
            username="watchdogvpn",
            password="secret-pass",
        )

        config = self.driver.generate_singbox_config(profile, lan_proxy=lan_proxy)
        inbounds = {inbound["tag"]: inbound for inbound in config["inbounds"]}

        self.assertEqual(inbounds["watchdogvpn-socks-in"]["listen"], "127.0.0.1")
        self.assertEqual(inbounds["watchdogvpn-http-in"]["listen"], "127.0.0.1")
        self.assertEqual(inbounds["watchdogvpn-lan-socks-in"]["listen"], "192.168.0.228")
        self.assertEqual(inbounds["watchdogvpn-lan-socks-in"]["listen_port"], 2080)
        self.assertEqual(
            inbounds["watchdogvpn-lan-socks-in"]["users"],
            [{"username": "watchdogvpn", "password": "secret-pass"}],
        )
        self.assertEqual(inbounds["watchdogvpn-lan-http-in"]["listen"], "192.168.0.228")
        self.assertEqual(inbounds["watchdogvpn-lan-http-in"]["listen_port"], 2081)
        self.assertEqual(
            inbounds["watchdogvpn-lan-http-in"]["users"],
            [{"username": "watchdogvpn", "password": "secret-pass"}],
        )
        self.assertFalse(inbounds["watchdogvpn-lan-http-in"]["set_system_proxy"])
        self.assertNotIn("direct", {outbound["tag"] for outbound in config["outbounds"]})

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    def test_lan_proxy_block_final_policy_rejects_without_direct_outbound(
        self, bind_mock, write_mock
    ) -> None:
        profile = self._profile(
            ProtocolType.VLESS,
            host="vless.example.com",
            port=443,
            uuid="uuid-1",
        )
        lan_proxy = LANProxyRuntimeConfig(
            bind_address="192.168.0.228",
            socks_port=2080,
            http_port=2081,
            username="watchdogvpn",
            password="secret-pass",
        )

        config = self.driver.generate_singbox_config(
            profile,
            mode="rules",
            groups=[],
            final_policy="block",
            lan_proxy=lan_proxy,
        )

        self.assertEqual(config["route"]["rules"], [{"action": "reject"}])
        self.assertFalse(
            any(rule.get("outbound") == "direct" for rule in config["route"]["rules"])
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
            (
                ProtocolType.WIREGUARD,
                {
                    "host": "wg.example.com",
                    "port": 51820,
                    "address": "10.0.0.2/32",
                    "private_key": "priv",
                    "public_key": "pub",
                },
            ),
            (ProtocolType.SOCKS, {"host": "socks.example.com", "port": 1080, "username": "user", "password": "pass"}),
            (ProtocolType.HTTP, {"host": "http.example.com", "port": 8080, "username": "user", "password": "pass"}),
        ]
        for protocol, cfg in cases:
            with self.subTest(protocol=protocol):
                profile = self._profile(protocol, **cfg)
                config = self.driver.generate_singbox_config(profile)
                if protocol is ProtocolType.WIREGUARD:
                    self.assertEqual(config["endpoints"][0]["type"], "wireguard")
                else:
                    self.assertEqual(config["outbounds"][0]["type"], protocol.value if protocol is not ProtocolType.SHADOWSOCKS else "shadowsocks")
                self.assertEqual(config["inbounds"][1]["type"], "http")
        self.assertEqual(write_mock.call_count, len(cases))

    @patch.object(SingBoxDriver, "_write_config")
    def test_generate_singbox_config_rejects_unsupported(self, write_mock) -> None:
        profile = self._profile(ProtocolType.AMNEZIAWG)
        with self.assertRaises(ValueError):
            self.driver.generate_singbox_config(profile)

    @patch.object(SingBoxDriver, "_write_config")
    def test_generation_never_uses_profile_identifier_as_a_secret(self, write_mock) -> None:
        profile = self._profile(
            ProtocolType.TROJAN,
            id="display-id-is-not-a-password",
            host="trojan.example.com",
            port=443,
        )

        with self.assertRaisesRegex(ValueError, "non-empty password"):
            self.driver.generate_singbox_config(profile)
        write_mock.assert_not_called()

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
        endpoint = config["endpoints"][0]
        self.assertEqual(endpoint["type"], "wireguard")
        self.assertEqual(endpoint["address"], ["10.0.0.2/32", "fd00::2/128"])
        self.assertEqual(endpoint["private_key"], "private-key")
        self.assertEqual(endpoint["mtu"], 1420)
        self.assertEqual(endpoint["peers"][0]["address"], "wg.example.com")
        self.assertEqual(endpoint["peers"][0]["port"], 51820)
        self.assertEqual(endpoint["peers"][0]["public_key"], "public-key")
        self.assertEqual(endpoint["peers"][0]["allowed_ips"], ["0.0.0.0/0", "::/0"])
        self.assertEqual(config["route"]["rules"], [{"action": "route", "outbound": endpoint["tag"]}])

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
    def test_generate_singbox_config_default_mode_is_global(self, bind_mock, write_mock) -> None:
        profile = self._profile(ProtocolType.VLESS, host="vless.example.com", port=443, uuid="uuid-1")
        config = self.driver.generate_singbox_config(profile)
        self.assertEqual(config["route"]["rules"], [{"action": "route", "outbound": "vless-demo"}])
        self.assertNotIn("direct", [o.get("tag") for o in config["outbounds"]])
        self.assertFalse(any(i["type"] == "tun" for i in config["inbounds"]))
        # base SOCKS+HTTP inbound must stay present regardless of mode —
        # health_check() depends on it (see Task 11.5 validation notes).
        self.assertTrue(any(i["tag"] == "watchdogvpn-socks-in" for i in config["inbounds"]))

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    def test_generate_singbox_config_direct_mode_routes_to_direct_outbound(
        self, bind_mock, write_mock
    ) -> None:
        profile = self._profile(ProtocolType.VLESS, host="vless.example.com", port=443, uuid="uuid-1")
        config = self.driver.generate_singbox_config(profile, mode="direct")
        self.assertEqual(config["route"]["rules"], [{"action": "route", "outbound": "direct"}])
        direct_outbounds = [o for o in config["outbounds"] if o.get("tag") == "direct"]
        self.assertEqual(len(direct_outbounds), 1)
        self.assertEqual(direct_outbounds[0]["type"], "direct")

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    def test_generate_singbox_config_tun_mode_adds_tun_inbound_and_routes_global(
        self, bind_mock, write_mock
    ) -> None:
        profile = self._profile(ProtocolType.VLESS, host="vless.example.com", port=443, uuid="uuid-1")
        config = self.driver.generate_singbox_config(profile, mode="tun")
        tun_inbounds = [i for i in config["inbounds"] if i["type"] == "tun"]
        self.assertEqual(len(tun_inbounds), 1)
        self.assertEqual(tun_inbounds[0]["tag"], "watchdogvpn-tun-in")
        self.assertTrue(tun_inbounds[0]["strict_route"])
        self.assertTrue(tun_inbounds[0]["auto_redirect"])
        self.assertEqual(config["route"]["rules"], [{"action": "route", "outbound": "vless-demo"}])
        # SOCKS+HTTP inbound stays present alongside TUN.
        self.assertTrue(any(i["tag"] == "watchdogvpn-socks-in" for i in config["inbounds"]))

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value="enp0s8")
    def test_tun_config_routes_active_ssh_peers_direct_before_all_other_rules(self, bind_mock, write_mock) -> None:
        profile = self._profile(ProtocolType.VLESS, host="vless.example.com", port=443, uuid="uuid-1")
        config = self.driver.generate_singbox_config(
            profile, mode="tun", management_peers=("198.51.100.9", "2001:db8::9")
        )
        self.assertEqual(
            config["route"]["rules"][:2],
            [
                {"ip_cidr": ["198.51.100.9/32"], "action": "route", "outbound": "direct"},
                {"ip_cidr": ["2001:db8::9/128"], "action": "route", "outbound": "direct"},
            ],
        )
        direct = next(outbound for outbound in config["outbounds"] if outbound["tag"] == "direct")
        self.assertEqual(direct["bind_interface"], "enp0s8")

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value="must-not-be-used")
    def test_native_transport_companion_uses_native_direct_and_separate_management_outbounds(
        self, bind_mock, write_mock
    ) -> None:
        profile = self._profile(ProtocolType.AMNEZIAWG, raw="[Interface]\nAddress = 10.0.0.2/32")
        config = self.driver.generate_singbox_config(
            profile,
            mode="rules",
            capture_modes=("local_proxy", "tun"),
            native_transport=True,
            native_bypass_cidrs=("138.124.58.47/32",),
            management_routes={"198.51.100.9": "enp0s8", "2001:db8::9": "eth0"},
        )

        self.assertEqual(
            config["route"]["rules"][:3],
            [
                {
                    "ip_cidr": ["138.124.58.47/32"],
                    "network": "udp",
                    "action": "bypass",
                },
                {
                    "ip_cidr": ["198.51.100.9/32"],
                    "action": "route",
                    "outbound": "watchdogvpn-management-1",
                },
                {
                    "ip_cidr": ["2001:db8::9/128"],
                    "action": "route",
                    "outbound": "watchdogvpn-management-2",
                },
            ],
        )
        outbounds = {outbound["tag"]: outbound for outbound in config["outbounds"]}
        self.assertEqual(outbounds["direct"], {"type": "direct", "tag": "direct"})
        self.assertEqual(outbounds["watchdogvpn-management-1"]["bind_interface"], "enp0s8")
        self.assertEqual(outbounds["watchdogvpn-management-2"]["bind_interface"], "eth0")
        self.assertNotIn("must-not-be-used", repr(config))
        self.assertTrue(any(inbound["type"] == "tun" for inbound in config["inbounds"]))

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    def test_generate_singbox_config_proxy_mode_routes_global_no_extra_inbound(
        self, bind_mock, write_mock
    ) -> None:
        profile = self._profile(ProtocolType.VLESS, host="vless.example.com", port=443, uuid="uuid-1")
        config = self.driver.generate_singbox_config(profile, mode="proxy")
        self.assertEqual(config["route"]["rules"], [{"action": "route", "outbound": "vless-demo"}])
        self.assertFalse(any(i["type"] == "tun" for i in config["inbounds"]))

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    def test_generate_singbox_config_rules_mode_generates_route_from_groups(
        self, bind_mock, write_mock
    ) -> None:
        profile = self._profile(ProtocolType.VLESS, host="vless.example.com", port=443, uuid="uuid-1")
        groups = [
            RuleGroup(
                name="block",
                rules=[Rule(id="b1", action="block", conditions={"domain_suffix": [".ads.com"]})],
            ),
            RuleGroup(
                name="app",
                rules=[Rule(id="a1", action="direct", conditions={"process_name": ["steam"]})],
            ),
        ]
        config = self.driver.generate_singbox_config(profile, mode="rules", groups=groups)
        self.assertEqual(
            config["route"]["rules"],
            [
                {"domain_suffix": [".ads.com"], "action": "reject"},
                {"process_name": ["steam"], "action": "route", "outbound": "direct"},
                {"action": "route", "outbound": "vless-demo"},
            ],
        )
        direct_outbounds = [o for o in config["outbounds"] if o.get("tag") == "direct"]
        self.assertEqual(len(direct_outbounds), 1)

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    def test_generate_singbox_config_maps_chain_plan_to_stable_detour_tags(
        self, bind_mock, write_mock
    ) -> None:
        active = self._profile(
            ProtocolType.VLESS,
            id="active",
            name="active",
            host="active.example",
            port=443,
            uuid="active",
        )
        hop_one = self._profile(
            ProtocolType.VLESS,
            id="hop-one",
            name="hop-one",
            host="hop-one.example",
            port=443,
            uuid="hop-one",
        )
        hop_two = self._profile(
            ProtocolType.VLESS,
            id="hop-two",
            name="hop-two",
            host="hop-two.example",
            port=443,
            uuid="hop-two",
        )
        plan = ChainRuntimePlan(
            route_action="chain:work-safe",
            chain_id="work-safe",
            status=ChainRuntimeStatus.RESOLVED,
            dns_path_status=ChainDNSPathStatus.CHAIN_OWNED,
            route_outbound_tag="watchdogvpn-chain-work-safe-hop-2",
            hops=(
                ChainRuntimeHopPlan(
                    index=1,
                    hop_type="profile",
                    target="hop-one",
                    status=ChainHopRuntimeStatus.RESOLVED,
                    outbound_tag="watchdogvpn-chain-work-safe-hop-1",
                    resolved_profile_id="hop-one",
                    resolved_profile=hop_one,
                ),
                ChainRuntimeHopPlan(
                    index=2,
                    hop_type="profile",
                    target="hop-two",
                    status=ChainHopRuntimeStatus.RESOLVED,
                    outbound_tag="watchdogvpn-chain-work-safe-hop-2",
                    resolved_profile_id="hop-two",
                    resolved_profile=hop_two,
                ),
            ),
        )

        config = self.driver.generate_singbox_config(
            active,
            mode="rules",
            groups=[
                RuleGroup(
                    name="custom",
                    rules=[
                        Rule(
                            id="chain",
                            action="chain:work-safe",
                            conditions={"domain": ["example.com"]},
                        )
                    ],
                )
            ],
            chain_runtime_plans={"chain:work-safe": plan},
        )

        outbounds = {outbound["tag"]: outbound for outbound in config["outbounds"]}
        self.assertNotIn("detour", outbounds["watchdogvpn-chain-work-safe-hop-1"])
        self.assertEqual(
            outbounds["watchdogvpn-chain-work-safe-hop-2"]["detour"],
            "watchdogvpn-chain-work-safe-hop-1",
        )
        self.assertEqual(
            config["route"]["rules"][0],
            {
                "domain": ["example.com"],
                "action": "route",
                "outbound": "watchdogvpn-chain-work-safe-hop-2",
            },
        )

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    def test_generate_singbox_config_uses_chain_outbound_for_global_chain_dns(
        self, bind_mock, write_mock
    ) -> None:
        active = self._profile(
            ProtocolType.VLESS,
            id="active",
            name="active",
            host="active.example",
            port=443,
            uuid="active",
        )
        hop_one = self._profile(
            ProtocolType.VLESS,
            id="hop-one",
            name="hop-one",
            host="hop-one.example",
            port=443,
            uuid="hop-one",
        )
        plan = ChainRuntimePlan(
            route_action="chain:work-safe",
            chain_id="work-safe",
            status=ChainRuntimeStatus.RESOLVED,
            dns_path_status=ChainDNSPathStatus.CHAIN_OWNED,
            route_outbound_tag="watchdogvpn-chain-work-safe-hop-1",
            hops=(
                ChainRuntimeHopPlan(
                    index=1,
                    hop_type="profile",
                    target="hop-one",
                    status=ChainHopRuntimeStatus.RESOLVED,
                    outbound_tag="watchdogvpn-chain-work-safe-hop-1",
                    resolved_profile_id="hop-one",
                    resolved_profile=hop_one,
                ),
            ),
        )
        dns_policy = DNSPolicy(
            channels={
                DNSChannelName.PROXY: DNSChannel(
                    name=DNSChannelName.PROXY,
                    resolvers=[Resolver(uri="https://1.1.1.1/dns-query")],
                )
            }
        )

        config = self.driver.generate_singbox_config(
            active,
            dns_policy=dns_policy,
            mode="global",
            final_policy="chain:work-safe",
            chain_runtime_plans={"chain:work-safe": plan},
        )

        proxy_servers = [
            server
            for server in config["dns"]["servers"]
            if server.get("tag") == "watchdogvpn-proxy-1"
        ]
        self.assertEqual(proxy_servers[0]["detour"], "watchdogvpn-chain-work-safe-hop-1")
        self.assertEqual(
            config["route"]["rules"][-1],
            {"action": "route", "outbound": "watchdogvpn-chain-work-safe-hop-1"},
        )

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    def test_generate_singbox_config_rules_mode_declares_verified_local_rule_sets(
        self, bind_mock, write_mock
    ) -> None:
        profile = self._profile(ProtocolType.VLESS, host="vless.example.com", port=443, uuid="uuid-1")
        groups = [
            RuleGroup(
                name="custom",
                rules=[
                    Rule(
                        id="rs",
                        action="block",
                        conditions={"ruleset_remote": ["remote-ads"]},
                    )
                ],
            )
        ]

        config = self.driver.generate_singbox_config(
            profile,
            mode="rules",
            groups=groups,
            rule_set_tags={"remote-ads": "wd-rule-set-abc"},
            rule_set_declarations=[
                {
                    "type": "local",
                    "tag": "wd-rule-set-abc",
                    "format": "source",
                    "path": "/tmp/ads.json",
                }
            ],
        )

        self.assertEqual(config["route"]["rule_set"][0]["tag"], "wd-rule-set-abc")
        self.assertEqual(config["route"]["rules"][0], {"rule_set": ["wd-rule-set-abc"], "action": "reject"})

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    def test_generate_singbox_config_rules_mode_with_no_groups_falls_back_to_final_policy(
        self, bind_mock, write_mock
    ) -> None:
        profile = self._profile(ProtocolType.VLESS, host="vless.example.com", port=443, uuid="uuid-1")
        config = self.driver.generate_singbox_config(
            profile, mode="rules", groups=None, final_policy="block"
        )
        self.assertEqual(config["route"]["rules"], [{"action": "reject"}])

    @patch.object(SingBoxDriver, "_write_config")
    def test_generate_singbox_config_rejects_unsupported_mode(self, write_mock) -> None:
        profile = self._profile(ProtocolType.VLESS, host="vless.example.com", port=443, uuid="uuid-1")
        with self.assertRaises(ValueError):
            self.driver.generate_singbox_config(profile, mode="bogus")

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value="enp4s0")
    def test_generate_singbox_config_direct_outbound_binds_to_detected_interface(
        self, bind_mock, write_mock
    ) -> None:
        # Regression test: under strict_route, a "direct" outbound with no
        # bind_interface has its own egress traffic recaptured by the TUN's
        # system-wide route capture, black-holing all direct/default traffic
        # and DNS (confirmed via live traffic reproduction in Task 12.5).
        profile = self._profile(ProtocolType.VLESS, host="vless.example.com", port=443, uuid="uuid-1")
        config = self.driver.generate_singbox_config(profile, mode="direct")
        direct_outbounds = [o for o in config["outbounds"] if o.get("tag") == "direct"]
        self.assertEqual(len(direct_outbounds), 1)
        self.assertEqual(direct_outbounds[0]["bind_interface"], "enp4s0")

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value="enp4s0")
    def test_generate_singbox_config_rules_mode_direct_outbound_binds_to_detected_interface(
        self, bind_mock, write_mock
    ) -> None:
        profile = self._profile(ProtocolType.VLESS, host="vless.example.com", port=443, uuid="uuid-1")
        groups = [
            RuleGroup(
                name="app",
                rules=[Rule(id="a1", action="direct", conditions={"process_name": ["steam"]})],
            ),
        ]
        config = self.driver.generate_singbox_config(profile, mode="rules", groups=groups)
        direct_outbounds = [o for o in config["outbounds"] if o.get("tag") == "direct"]
        self.assertEqual(len(direct_outbounds), 1)
        self.assertEqual(direct_outbounds[0]["bind_interface"], "enp4s0")

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    def test_generate_singbox_config_proxy_only_dns_does_not_loop_outbound_resolver(
        self, bind_mock, write_mock
    ) -> None:
        # Regression: with only a "proxy" DNS channel configured (no direct/
        # bootstrap fallback), resolving the profile outbound's own server
        # hostname through that channel would dial through the same outbound
        # it is trying to resolve for — a DNS query loopback sing-box
        # correctly rejects at runtime (confirmed via live traffic
        # reproduction, Task 12.5). The outbound must not be assigned a
        # domain_resolver in this case.
        profile = self._profile(ProtocolType.VLESS, host="vless.example.com", port=443, uuid="uuid-1")
        dns_policy = DNSPolicy(
            channels={
                DNSChannelName.PROXY: DNSChannel(
                    name=DNSChannelName.PROXY,
                    resolvers=[Resolver(uri="udp://1.1.1.1")],
                ),
            },
        )
        config = self.driver.generate_singbox_config(profile, dns_policy=dns_policy)
        self.assertNotIn("domain_resolver", config["outbounds"][0])
        self.assertNotIn("default_domain_resolver", config.get("route", {}))

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value="enp4s0")
    def test_generate_singbox_config_direct_mode_reuses_dns_direct_outbound(
        self, bind_mock, write_mock
    ) -> None:
        profile = self._profile(ProtocolType.VLESS, host="vless.example.com", port=443, uuid="uuid-1")
        dns_policy = DNSPolicy(
            channels={
                DNSChannelName.DIRECT: DNSChannel(
                    name=DNSChannelName.DIRECT,
                    resolvers=[Resolver(uri="udp://9.9.9.9")],
                ),
            }
        )
        config = self.driver.generate_singbox_config(profile, dns_policy=dns_policy, mode="direct")
        direct_outbounds = [o for o in config["outbounds"] if o.get("tag") == "direct"]
        # DNS policy and "direct" mode both want a "direct" outbound — must
        # not be added twice, and the DNS domain_resolver must survive.
        self.assertEqual(len(direct_outbounds), 1)
        self.assertEqual(direct_outbounds[0]["domain_resolver"], "watchdogvpn-direct-1")
        self.assertEqual(config["route"]["rules"][-1], {"action": "route", "outbound": "direct"})

    @patch.object(SingBoxDriver, "_write_config")
    def test_generate_singbox_config_rejects_unsupported_final_policy(self, write_mock) -> None:
        profile = self._profile(ProtocolType.VLESS, host="vless.example.com", port=443, uuid="uuid-1")
        with self.assertRaises(ValueError):
            self.driver.generate_singbox_config(profile, mode="rules", final_policy="group:x")

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
        # Regression: the profile's own outbound must resolve its own server
        # hostname via the direct/bootstrap channel, never fakeip and never a
        # resolver that itself dials through this same outbound (a "proxy"
        # channel resolver, or "final" falling back to it) — both previously
        # made the tunnel try to dial an address it could never reach and
        # time out (confirmed via live traffic reproduction with sing-box
        # debug logs, Task 12.5: fakeip is a synthetic, non-dialable
        # placeholder, and a proxied resolver creates a DNS query loopback
        # since resolving the server needs the tunnel, which needs the
        # server resolved first).
        self.assertEqual(config["outbounds"][0]["domain_resolver"], "watchdogvpn-direct-1")
        self.assertEqual(len(config["outbounds"]), 2)
        direct_outbound = config["outbounds"][1]
        self.assertEqual(direct_outbound["type"], "direct")
        self.assertEqual(direct_outbound["tag"], "direct")
        self.assertEqual(direct_outbound["domain_resolver"], "watchdogvpn-direct-1")
        self.assertEqual(config["dns"]["final"], "watchdogvpn-final-1")
        self.assertEqual(config["route"]["default_domain_resolver"], "watchdogvpn-direct-1")
        self.assertEqual(config["dns"]["rules"], [])
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
            {"action": "sniff"},
            {"protocol": ["dns"], "action": "hijack-dns"},
            {
                "inbound": [
                    "watchdogvpn-dns-udp-in",
                    "watchdogvpn-dns-tcp-in",
                ],
                "action": "hijack-dns",
            },
            {"action": "route", "outbound": "vless-demo"},
        ])
        dns_servers = {server["tag"]: server for server in config["dns"]["servers"]}
        self.assertEqual(dns_servers["watchdogvpn-fakeip"]["type"], "fakeip")
        self.assertEqual(dns_servers["watchdogvpn-direct-1"]["type"], "local")
        self.assertEqual(dns_servers["watchdogvpn-proxy-1"]["detour"], "vless-demo")
        self.assertEqual(dns_servers["watchdogvpn-final-1"]["server"], "9.9.9.9")

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    def test_generate_singbox_config_routes_proxy_dns_diversion_to_fakeip(
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
            rules_enabled=True,
            rules=[
                DNSRule(
                    id="probe",
                    pattern="domain:fakeip-probe.watchdogvpn-test",
                    channel=DNSChannelName.PROXY,
                )
            ],
            channels={
                DNSChannelName.DIRECT: DNSChannel(
                    name=DNSChannelName.DIRECT,
                    resolvers=[Resolver(uri="local")],
                ),
                DNSChannelName.PROXY: DNSChannel(
                    name=DNSChannelName.PROXY,
                    resolvers=[Resolver(uri="https://1.1.1.1/dns-query")],
                ),
            },
        )

        config = self.driver.generate_singbox_config(
            profile,
            dns_policy=dns_policy,
            mode="tun",
        )

        self.assertEqual(config["dns"]["rules"], [
            {
                "domain": ["fakeip-probe.watchdogvpn-test"],
                "server": "watchdogvpn-fakeip",
            }
        ])
        self.assertEqual(config["route"]["rules"][:3], [
            {"action": "sniff"},
            {"protocol": ["dns"], "action": "hijack-dns"},
            {
                "inbound": [
                    "watchdogvpn-dns-udp-in",
                    "watchdogvpn-dns-tcp-in",
                ],
                "action": "hijack-dns",
            },
        ])

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    def test_generate_singbox_config_prepends_app_policy_dns_rules(
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
            },
        )
        app_policy = AppPolicy(
            enabled=True,
            mode="blacklist",
            rules=[
                AppPolicyRule(
                    id="curl",
                    action="direct",
                    match={"process_name": ["curl"]},
                ),
                AppPolicyRule(
                    id="blocked",
                    action="block",
                    match={"process_path": ["/usr/bin/blocked"]},
                ),
                AppPolicyRule(
                    id="current",
                    action="current",
                    match={"user": ["gabodev"]},
                ),
            ],
        )

        config = self.driver.generate_singbox_config(
            profile,
            dns_policy=dns_policy,
            mode="rules",
            app_policy=app_policy,
        )

        self.assertEqual(config["dns"]["rules"][:3], [
            {"process_name": ["curl"], "server": "watchdogvpn-direct-1"},
            {"process_path": ["/usr/bin/blocked"], "action": "reject"},
            {"user": ["gabodev"], "server": "watchdogvpn-fakeip"},
        ])
        self.assertIn(
            {"process_name": ["curl"], "action": "route", "outbound": "direct"},
            config["route"]["rules"],
        )

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    def test_generate_singbox_config_rejects_direct_app_dns_without_direct_channel(
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
                DNSChannelName.PROXY: DNSChannel(
                    name=DNSChannelName.PROXY,
                    resolvers=[Resolver(uri="https://1.1.1.1/dns-query")],
                ),
            },
        )
        app_policy = AppPolicy(
            enabled=True,
            mode="blacklist",
            rules=[
                AppPolicyRule(
                    id="curl",
                    action="direct",
                    match={"process_name": ["curl"]},
                ),
            ],
        )

        config = self.driver.generate_singbox_config(
            profile,
            dns_policy=dns_policy,
            mode="rules",
            app_policy=app_policy,
        )

        self.assertEqual(
            config["dns"]["rules"][0],
            {"process_name": ["curl"], "action": "reject"},
        )

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
        self.assertEqual(config["route"]["rules"], [{"action": "route", "outbound": "vless-demo"}])
        self.assertFalse(
            any(
                inbound["tag"].startswith("watchdogvpn-dns-")
                for inbound in config["inbounds"]
            )
        )

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    def test_generate_singbox_config_rules_mode_includes_app_policy(
        self, bind_mock, write_mock
    ) -> None:
        profile = self._profile(ProtocolType.VLESS, host="vless.example.com", port=443, uuid="uuid-1")
        policy = AppPolicy(
            enabled=True,
            mode="blacklist",
            rules=[
                AppPolicyRule(
                    id="curl",
                    action="block",
                    match={"process_path": ["/usr/bin/curl"]},
                )
            ],
        )

        config = self.driver.generate_singbox_config(
            profile,
            mode="rules",
            app_policy=policy,
            capture_modes=("local_proxy", "tun"),
        )

        tun_inbounds = [i for i in config["inbounds"] if i["type"] == "tun"]
        self.assertEqual(len(tun_inbounds), 1)
        self.assertEqual(tun_inbounds[0]["interface_name"], "wdvpn-tun0")
        self.assertTrue(tun_inbounds[0]["strict_route"])
        self.assertTrue(tun_inbounds[0]["auto_redirect"])

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    def test_generate_singbox_config_rules_mode_tun_follows_capture_modes_not_app_policy(
        self, bind_mock, write_mock
    ) -> None:
        # Field regression (Phase 23 Task 23.3.3): TUN inclusion must be
        # driven by the operator's explicit capture_modes setting, not by
        # whether app policy happens to be enabled. A routine
        # "watchdog app-policy disable" must never silently downgrade a
        # rules-mode connection to proxy-only with no system traffic
        # protection.
        profile = self._profile(ProtocolType.VLESS, host="vless.example.com", port=443, uuid="uuid-1")
        enabled_policy = AppPolicy(enabled=True, mode="blacklist", rules=[])
        disabled_policy = AppPolicy(enabled=False, mode="blacklist", rules=[])

        # app_policy enabled but capture_modes has no "tun": no TUN inbound.
        config_no_tun = self.driver.generate_singbox_config(
            profile,
            mode="rules",
            app_policy=enabled_policy,
            capture_modes=("local_proxy",),
        )
        self.assertEqual([i for i in config_no_tun["inbounds"] if i["type"] == "tun"], [])

        # app_policy disabled but capture_modes includes "tun": TUN inbound
        # still gets created - system traffic protection does not depend on
        # app policy being on.
        config_with_tun = self.driver.generate_singbox_config(
            profile,
            mode="rules",
            app_policy=disabled_policy,
            capture_modes=("local_proxy", "tun"),
        )
        self.assertEqual(len([i for i in config_with_tun["inbounds"] if i["type"] == "tun"]), 1)

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    def test_generate_singbox_config_default_direct_plus_app_current_policy(
        self, bind_mock, write_mock
    ) -> None:
        profile = self._profile(ProtocolType.VLESS, host="vless.example.com", port=443, uuid="uuid-1")
        policy = AppPolicy(
            enabled=True,
            mode="blacklist",
            default_action="direct",
            rules=[
                AppPolicyRule(
                    id="python-current",
                    action="current",
                    match={"process_path": ["/usr/bin/python3.14"]},
                )
            ],
        )

        config = self.driver.generate_singbox_config(
            profile,
            mode="rules",
            app_policy=policy,
        )

        self.assertEqual(
            config["route"]["rules"],
            [
                {
                    "process_path": ["/usr/bin/python3.14"],
                    "action": "route",
                    "outbound": "vless-demo",
                },
                {"action": "route", "outbound": "direct"},
                {"action": "route", "outbound": "vless-demo"},
            ],
        )

    @patch.object(SingBoxDriver, "_write_config")
    @patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None)
    def test_generate_singbox_config_ignores_app_policy_outside_rules_mode(
        self, bind_mock, write_mock
    ) -> None:
        profile = self._profile(ProtocolType.VLESS, host="vless.example.com", port=443, uuid="uuid-1")
        policy = AppPolicy(
            enabled=True,
            mode="whitelist",
            default_action="block",
            rules=[
                AppPolicyRule(
                    id="curl",
                    action="block",
                    match={"process_path": ["/usr/bin/curl"]},
                )
            ],
        )

        config = self.driver.generate_singbox_config(
            profile,
            mode="global",
            app_policy=policy,
        )

        self.assertFalse(any(i["type"] == "tun" for i in config["inbounds"]))
        self.assertEqual(config["route"]["rules"], [{"action": "route", "outbound": "vless-demo"}])

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

    def _status(
        self,
        *,
        ports: tuple[int, ...] | None = None,
        owned_processes: tuple[OwnedProcess, ...] = (),
        nft_observation: tuple[bool, bool] | None = None,
        residue: tuple[tuple[str, ...], tuple[str, ...]] = ((), ()),
    ):
        process = self.driver._process
        alive = process is not None and process.poll() is None
        effective_ports = (2080, 2081) if ports is None and alive else ports or ()
        effective_nft = (
            (self.driver._tun_expected, self.driver._tun_expected)
            if nft_observation is None
            else nft_observation
        )
        with (
            patch.object(
                self.driver,
                "_owned_proxy_runtime_observation",
                return_value=(
                    owned_processes,
                    TCPListenerObservation(True, effective_ports),
                ),
            ),
            patch.object(
                self.driver,
                "_singbox_auto_redirect_observation",
                return_value=effective_nft,
            ),
            patch.object(
                self.driver,
                "_discover_singbox_tun_residue",
                return_value=residue,
            ),
        ):
            return self.driver.status()

    def test_direct_tun_connect_refuses_before_binary_or_process_mutation(self) -> None:
        with (
            patch.object(SingBoxDriver, "_active_ssh_management_peers", return_value=("198.51.100.9",)),
            patch.object(SingBoxDriver, "_outbound_bind_interface", return_value=None),
            patch.object(SingBoxDriver, "find_singbox_binary") as binary_mock,
            patch.object(SingBoxDriver, "generate_singbox_config") as generate_mock,
        ):
            self.assertFalse(self.driver.connect(self.profile, mode="tun"))

        binary_mock.assert_not_called()
        generate_mock.assert_not_called()
        self.assertIn("TUN refused", self.driver.last_error)

    @patch.object(SingBoxDriver, "find_singbox_binary", return_value="/usr/bin/sing-box")
    @patch.object(SingBoxDriver, "generate_singbox_config")
    @patch("drivers.singbox_driver.subprocess.Popen")
    def test_connect_starts_process(self, popen_mock, generate_mock, binary_mock) -> None:
        process = popen_mock.return_value
        process.poll.return_value = None
        process.pid = 4242

        with patch.object(SingBoxDriver, "health_check", return_value="ok"):
            self.assertTrue(self.driver.connect(self.profile))
            generate_mock.assert_called_once_with(
                self.profile,
                dns_policy=None,
                mode="global",
                groups=None,
                app_policy=None,
                final_policy="current_profile",
                rule_set_tags=None,
                rule_set_declarations=None,
                chain_runtime_plans=None,
                capture_modes=None,
            )
            popen_mock.assert_called_once()
            self.assertIs(self.driver._process, process)
            self.assertIs(self.driver._active_profile, self.profile)
            self.assertIsNotNone(self.driver._connected_at)
            args = popen_mock.call_args.args[0]
            self.assertEqual(args[:3], ["/usr/bin/sing-box", "run", "-c"])
            self.assertEqual(args[3], str(self.driver._config_path))

    @patch.object(SingBoxDriver, "find_singbox_binary", return_value="/usr/bin/sing-box")
    @patch.object(SingBoxDriver, "generate_singbox_config")
    @patch("drivers.singbox_driver.record_child_process")
    @patch("drivers.singbox_driver.subprocess.Popen")
    def test_connect_rejects_foreign_proxy_listener(
        self, popen_mock, record_mock, generate_mock, binary_mock
    ) -> None:
        process = popen_mock.return_value
        process.poll.return_value = None
        process.pid = 4242

        with (
            patch.object(SingBoxDriver, "_wait_for_proxy_port", return_value=True),
            patch.object(
                SingBoxDriver,
                "_owned_proxy_runtime_observation",
                return_value=((), TCPListenerObservation(True, ())),
            ),
            patch.object(SingBoxDriver, "_append_log"),
            patch.object(self.driver, "disconnect") as disconnect_mock,
        ):
            self.assertFalse(self.driver.connect(self.profile))

        generate_mock.assert_called_once()
        record_mock.assert_called_once()
        disconnect_mock.assert_called_once_with()


    @patch.object(SingBoxDriver, "find_singbox_binary", return_value="/usr/bin/sing-box")
    @patch.object(SingBoxDriver, "generate_singbox_config")
    @patch("drivers.singbox_driver.subprocess.Popen")
    def test_connect_disconnects_stale_process_before_starting_new_one(
        self, popen_mock, generate_mock, binary_mock
    ) -> None:
        # Regression guard for WDCLI-001: reconnecting the same profile (or
        # any profile using the same driver type) must not silently
        # overwrite a still-running process, orphaning it.
        stale_process = unittest.mock.Mock()
        stale_process.poll.return_value = None
        self.driver._process = stale_process
        self.driver._active_profile = self.profile

        new_process = unittest.mock.Mock()
        new_process.poll.return_value = None
        new_process.pid = 9999
        popen_mock.return_value = new_process

        with patch.object(SingBoxDriver, "health_check", return_value="ok"):
            self.assertTrue(self.driver.connect(self.profile))

        stale_process.terminate.assert_called_once()
        self.assertIs(self.driver._process, new_process)

    @patch.object(SingBoxDriver, "find_singbox_binary", return_value="/usr/bin/sing-box")
    @patch.object(SingBoxDriver, "generate_singbox_config")
    @patch("drivers.singbox_driver.subprocess.Popen")
    def test_connect_forwards_dns_policy_to_generated_config(
        self, popen_mock, generate_mock, binary_mock
    ) -> None:
        process = popen_mock.return_value
        process.poll.return_value = None
        process.pid = 4242
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
            generate_mock.assert_called_once_with(
                self.profile,
                dns_policy=policy,
                mode="global",
                groups=None,
                app_policy=None,
                final_policy="current_profile",
                rule_set_tags=None,
                rule_set_declarations=None,
                chain_runtime_plans=None,
                capture_modes=None,
            )

    @patch.object(SingBoxDriver, "find_singbox_binary", return_value=None)
    @patch.object(SingBoxDriver, "generate_singbox_config")
    @patch("drivers.singbox_driver.subprocess.Popen")
    def test_connect_returns_false_when_binary_missing(self, popen_mock, generate_mock, binary_mock) -> None:
        self.assertFalse(self.driver.connect(self.profile))
        generate_mock.assert_not_called()
        popen_mock.assert_not_called()

    @patch.object(SingBoxDriver, "find_singbox_binary", return_value="/usr/bin/sing-box")
    @patch.object(SingBoxDriver, "generate_singbox_config")
    @patch("drivers.singbox_driver.subprocess.Popen")
    def test_connect_tun_defers_egress_authority_to_runtime(
        self, popen_mock, generate_mock, binary_mock
    ) -> None:
        process = popen_mock.return_value
        process.poll.return_value = None
        process.pid = 4242

        with (
            patch.object(SingBoxDriver, "_wait_for_proxy_port", return_value=True),
            patch.object(SingBoxDriver, "_wait_for_tun_interface", return_value=True),
            patch.object(SingBoxDriver, "_wait_for_tun_auto_redirect_ready", return_value=True),
            patch.object(SingBoxDriver, "_owned_proxy_egress_ready", return_value=True),
            patch.object(SingBoxDriver, "_ip_rule_lines", return_value=()),
        ):
            self.assertTrue(self.driver.connect(self.profile, mode="tun", management_peers=()))

        self.assertEqual(self.driver._active_mode, "tun")
        self.assertTrue(self.driver._tun_expected)

    @patch.object(SingBoxDriver, "find_singbox_binary", return_value="/usr/bin/sing-box")
    @patch.object(SingBoxDriver, "generate_singbox_config")
    @patch("drivers.singbox_driver.subprocess.Popen")
    def test_connect_fails_and_cleans_up_when_tun_auto_redirect_never_gets_ready(
        self, popen_mock, generate_mock, binary_mock
    ) -> None:
        process = popen_mock.return_value
        process.poll.return_value = None
        process.pid = 4242

        def mark_child_dead() -> bool:
            process.poll.return_value = 1
            return False

        with (
            patch.object(SingBoxDriver, "_wait_for_proxy_port", return_value=True),
            patch.object(SingBoxDriver, "_wait_for_tun_interface", return_value=True),
            patch.object(SingBoxDriver, "_owned_proxy_egress_ready", return_value=True),
            patch.object(SingBoxDriver, "_wait_for_tun_auto_redirect_ready", side_effect=mark_child_dead),
            patch.object(SingBoxDriver, "_ip_rule_lines", return_value=()),
            patch.object(self.driver, "_capture_tun_cleanup_state") as capture_mock,
            patch.object(self.driver, "_cleanup_tun_residue") as cleanup_mock,
        ):
            self.assertFalse(self.driver.connect(self.profile, mode="tun", management_peers=()))

        self.assertIsNone(self.driver._active_profile)
        self.assertIsNone(self.driver._connected_at)
        self.assertFalse(self.driver._tun_expected)
        self.assertGreaterEqual(capture_mock.call_count, 1)
        cleanup_mock.assert_called_once()

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

    @patch.object(SingBoxDriver, "_cleanup_tun_residue")
    @patch.object(SingBoxDriver, "_cleanup_runtime")
    def test_disconnect_cleans_tun_residue_after_child_crash(
        self, cleanup_mock, tun_cleanup_mock
    ) -> None:
        process = unittest.mock.Mock()
        process.poll.return_value = -9
        self.driver._process = process
        self.driver._tun_expected = True

        self.assertTrue(self.driver.disconnect())
        process.terminate.assert_not_called()
        process.kill.assert_not_called()
        tun_cleanup_mock.assert_called_once()
        cleanup_mock.assert_called_once()

    @patch.object(SingBoxDriver, "_cleanup_tun_residue")
    @patch.object(SingBoxDriver, "_cleanup_runtime")
    def test_disconnect_does_not_remove_tun_residue_when_process_survives_kill(
        self, cleanup_mock, tun_cleanup_mock
    ) -> None:
        process = unittest.mock.Mock()
        process.poll.return_value = None
        process.wait.side_effect = [
            subprocess.TimeoutExpired(cmd="sing-box", timeout=5),
            subprocess.TimeoutExpired(cmd="sing-box", timeout=5),
        ]
        self.driver._process = process
        self.driver._tun_expected = True

        self.assertFalse(self.driver.disconnect())
        process.terminate.assert_called_once()
        process.kill.assert_called_once()
        tun_cleanup_mock.assert_not_called()
        cleanup_mock.assert_called_once()

    def test_capture_tun_cleanup_state_tracks_added_rules_and_tables(self) -> None:
        self.driver._tun_rule_baseline = (
            "0:\tfrom all lookup local",
            "32766:\tfrom all lookup main",
            "32767:\tfrom all lookup default",
        )
        current_rules = (
            *self.driver._tun_rule_baseline,
            "1:\tfrom all lookup 1771114712",
            "9000:\tfrom all fwmark 0x2024 goto 9002",
            "9001:\tfrom all fwmark 0x2023 lookup 2022",
            "9002:\tfrom all nop",
            "32768:\tfrom all lookup 2022",
        )

        with (
            patch.object(self.driver, "_ip_rule_lines", return_value=current_rules),
            patch.object(
                self.driver,
                "_route_table_looks_like_watchdogvpn",
                side_effect=lambda table: table == "1771114712",
            ),
        ):
            self.driver._capture_tun_cleanup_state()

        self.assertEqual(
            self.driver._tun_cleanup_rule_prefs,
            ("1", "9000", "9001", "9002", "32768"),
        )
        self.assertEqual(
            self.driver._tun_cleanup_route_tables,
            ("1771114712", "2022"),
        )

    def test_capture_tun_cleanup_state_ignores_unmarked_unrelated_rule(self) -> None:
        self.driver._tun_rule_baseline = (
            "0:\tfrom all lookup local",
            "32766:\tfrom all lookup main",
            "32767:\tfrom all lookup default",
        )
        current_rules = (
            *self.driver._tun_rule_baseline,
            "100:\tfrom all lookup 424242",
        )

        with (
            patch.object(self.driver, "_ip_rule_lines", return_value=current_rules),
            patch.object(self.driver, "_route_table_looks_like_watchdogvpn", return_value=False),
        ):
            self.driver._capture_tun_cleanup_state()

        self.assertEqual(self.driver._tun_cleanup_rule_prefs, ())
        self.assertEqual(self.driver._tun_cleanup_route_tables, ())

    @patch("drivers.singbox_driver.shutil.which", side_effect=lambda name: f"/usr/bin/{name}")
    @patch("drivers.singbox_driver.subprocess.run")
    def test_cleanup_tun_residue_uses_captured_state(
        self, run_mock, which_mock
    ) -> None:
        self.driver._tun_cleanup_rule_prefs = ("1", "9000")
        self.driver._tun_cleanup_route_tables = ("1771114712", "2022")

        self.driver._cleanup_tun_residue()

        commands = [call.args[0] for call in run_mock.call_args_list]
        self.assertIn(["nft", "delete", "table", "inet", "sing-box"], commands)
        self.assertIn(["ip", "rule", "del", "pref", "1"], commands)
        self.assertIn(["ip", "rule", "del", "pref", "9000"], commands)
        self.assertNotIn(["ip", "rule", "del", "pref", "9001"], commands)
        self.assertIn(["ip", "route", "flush", "table", "1771114712"], commands)
        self.assertIn(["ip", "-6", "route", "flush", "table", "1771114712"], commands)
        self.assertIn(["ip", "route", "flush", "table", "2022"], commands)
        self.assertIn(["ip", "-6", "route", "flush", "table", "2022"], commands)

    @patch("drivers.singbox_driver.shutil.which", return_value="/usr/bin/nft")
    def test_apply_lan_gateway_installs_nft_rules_then_enables_forwarding(self, which_mock) -> None:
        gateway = LANGatewayRuntimeConfig(
            lan_interface="enp0s8",
            client_cidr="192.168.50.0/24",
            tunnel_interface="wdvpn-tun0",
        )
        self.driver._tun_expected = True
        commands: list[list[str]] = []

        with (
            patch.object(self.driver, "_run_cleanup_command") as cleanup_mock,
            patch.object(self.driver, "_run_gateway_required", side_effect=lambda command: commands.append(command) or True),
            patch.object(self.driver, "_read_ipv4_forward", return_value="0"),
            patch.object(self.driver, "_write_ipv4_forward") as write_forward_mock,
        ):
            self.assertTrue(self.driver._apply_lan_gateway(gateway))

        cleanup_mock.assert_called_once_with(["nft", "delete", "table", "inet", "watchdogvpn_lan_gateway"])
        self.assertIn(["nft", "add", "table", "inet", "watchdogvpn_lan_gateway"], commands)
        self.assertIn(
            [
                "nft",
                "add",
                "chain",
                "inet",
                "watchdogvpn_lan_gateway",
                "forward",
                "{",
                "type",
                "filter",
                "hook",
                "forward",
                "priority",
                "0;",
                "policy",
                "drop;",
                "}",
            ],
            commands,
        )
        self.assertIn(
            [
                "nft",
                "add",
                "rule",
                "inet",
                "watchdogvpn_lan_gateway",
                "forward",
                "iifname",
                "enp0s8",
                "oifname",
                "wdvpn-tun0",
                "ip",
                "saddr",
                "192.168.50.0/24",
                "accept",
            ],
            commands,
        )
        self.assertIn(
            [
                "nft",
                "add",
                "rule",
                "inet",
                "watchdogvpn_lan_gateway",
                "postrouting",
                "oifname",
                "wdvpn-tun0",
                "ip",
                "saddr",
                "192.168.50.0/24",
                "masquerade",
            ],
            commands,
        )
        write_forward_mock.assert_called_once_with("1")
        self.assertEqual(self.driver._lan_gateway_active, gateway)
        self.assertEqual(self.driver._lan_gateway_ip_forward_snapshot, "0")

    @patch("drivers.singbox_driver.shutil.which", return_value="/usr/bin/nft")
    def test_cleanup_lan_gateway_removes_table_and_restores_forwarding(self, which_mock) -> None:
        self.driver._lan_gateway_active = LANGatewayRuntimeConfig(
            lan_interface="enp0s8",
            client_cidr="192.168.50.0/24",
        )
        self.driver._lan_gateway_ip_forward_snapshot = "0"

        with (
            patch.object(self.driver, "_run_cleanup_command") as cleanup_mock,
            patch.object(self.driver, "_write_ipv4_forward") as write_forward_mock,
        ):
            self.driver._cleanup_lan_gateway()

        cleanup_mock.assert_called_once_with(["nft", "delete", "table", "inet", "watchdogvpn_lan_gateway"])
        write_forward_mock.assert_called_once_with("0")
        self.assertIsNone(self.driver._lan_gateway_active)
        self.assertIsNone(self.driver._lan_gateway_ip_forward_snapshot)

    @patch("drivers.singbox_driver.shutil.which", return_value="/usr/bin/nft")
    @patch.object(SingBoxDriver, "_run_capture_command")
    def test_singbox_auto_redirect_ready_requires_nft_table_and_base_chains(
        self, capture_mock, which_mock
    ) -> None:
        capture_mock.return_value.returncode = 0
        capture_mock.return_value.stdout = """
table inet sing-box {
    chain output {
        type route hook output priority mangle; policy accept;
    }
    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;
    }
}
"""

        self.assertTrue(self.driver._singbox_auto_redirect_ready())
        capture_mock.assert_called_once_with(["nft", "list", "table", "inet", "sing-box"])

    @patch("drivers.singbox_driver.shutil.which", return_value="/usr/bin/nft")
    @patch.object(SingBoxDriver, "_run_capture_command")
    def test_singbox_auto_redirect_ready_rejects_partial_nft_table(
        self, capture_mock, which_mock
    ) -> None:
        capture_mock.return_value.returncode = 0
        capture_mock.return_value.stdout = """
table inet sing-box {
    chain output {
    }
}
"""

        self.assertFalse(self.driver._singbox_auto_redirect_ready())

    def test_discover_singbox_tun_residue_uses_marks_and_tun_routes(self) -> None:
        current_rules = (
            "0:\tfrom all lookup local",
            "1:\tfrom all lookup 1771114712",
            "9000:\tfrom all fwmark 0x2024 goto 9002",
            "9001:\tfrom all fwmark 0x2023 lookup 2022",
            "9002:\tfrom all nop",
            "32766:\tfrom all lookup main",
            "32767:\tfrom all lookup default",
            "32768:\tfrom all lookup 2022",
        )

        def route_table_output(table: str, ipv6: bool = False) -> str:
            if table == "1771114712":
                return "default dev wdvpn-tun0 scope link\n"
            return ""

        with (
            patch.object(self.driver, "_ip_rule_lines", return_value=current_rules),
            patch.object(self.driver, "_route_table_output", side_effect=route_table_output),
        ):
            prefs, tables = self.driver._discover_singbox_tun_residue()

        self.assertEqual(prefs, ("1", "9000", "9001", "9002", "32768"))
        self.assertEqual(tables, ("1771114712", "2022"))

    def test_discover_singbox_tun_residue_can_include_orphaned_auto_route_rule(self) -> None:
        current_rules = (
            "0:\tfrom all lookup local",
            "1:\tfrom all lookup 1590681128",
            "32766:\tfrom all lookup main",
            "32767:\tfrom all lookup default",
        )

        with (
            patch.object(self.driver, "_ip_rule_lines", return_value=current_rules),
            patch.object(self.driver, "_route_table_output", return_value=""),
        ):
            prefs, tables = self.driver._discover_singbox_tun_residue(
                include_orphaned_auto_route_rule=True,
            )

        self.assertEqual(prefs, ("1",))
        self.assertEqual(tables, ("1590681128",))

    def test_discover_singbox_tun_residue_ignores_orphaned_auto_route_by_default(self) -> None:
        current_rules = (
            "0:\tfrom all lookup local",
            "1:\tfrom all lookup 1590681128",
            "32766:\tfrom all lookup main",
            "32767:\tfrom all lookup default",
        )

        with (
            patch.object(self.driver, "_ip_rule_lines", return_value=current_rules),
            patch.object(self.driver, "_route_table_output", return_value=""),
        ):
            prefs, tables = self.driver._discover_singbox_tun_residue()

        self.assertEqual(prefs, ())
        self.assertEqual(tables, ())

    @patch.object(SingBoxDriver, "_cleanup_tun_residue")
    def test_reconcile_stale_tun_state_skips_when_singbox_is_alive(self, cleanup_mock) -> None:
        with (
            patch.object(self.driver, "_singbox_process_alive", return_value=True),
            patch.object(self.driver, "_discover_singbox_tun_residue") as discover_mock,
        ):
            self.driver.reconcile_stale_tun_state()

        discover_mock.assert_not_called()
        cleanup_mock.assert_not_called()

    @patch.object(SingBoxDriver, "_cleanup_tun_residue")
    def test_reconcile_stale_tun_state_cleans_orphaned_residue(self, cleanup_mock) -> None:
        with (
            patch.object(self.driver, "_singbox_process_alive", return_value=False),
            patch.object(
                self.driver,
                "_discover_singbox_tun_residue",
                return_value=(("9000", "9001"), ("2022",)),
            ),
        ):
            self.driver.reconcile_stale_tun_state()

        self.assertEqual(self.driver._tun_cleanup_rule_prefs, ("9000", "9001"))
        self.assertEqual(self.driver._tun_cleanup_route_tables, ("2022",))
        cleanup_mock.assert_called_once()

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

    @patch.object(SingBoxDriver, "_tun_interface_active", return_value=False)
    def test_status_returns_standby_without_process(self, tun_mock) -> None:
        state = self._status()
        self.assertEqual(state.status, "standby")

    @patch.object(SingBoxDriver, "_tun_interface_active", return_value=True)
    def test_status_reports_runtime_mismatch_when_tun_interface_orphaned(self, tun_mock) -> None:
        state = self._status()
        self.assertEqual(state.status, "runtime_mismatch")
        self.assertEqual(state.runtime_mismatch_severity, "critical")
        self.assertIn("interface:wdvpn-tun0", state.runtime_artifacts)

    @patch.object(SingBoxDriver, "_tun_interface_active", return_value=False)
    def test_status_reports_runtime_mismatch_when_recorded_child_alive(self, tun_mock) -> None:
        state = self._status(
            owned_processes=(OwnedProcess(pid=4242, executable="sing-box"),)
        )
        self.assertEqual(state.status, "runtime_mismatch")
        self.assertIn("owned_process:sing-box", state.runtime_artifacts)

    @patch.object(SingBoxDriver, "_tun_interface_active", return_value=False)
    def test_status_reports_listener_only_orphan_as_critical_mismatch(self, tun_mock) -> None:
        state = self._status(ports=(2080,))

        self.assertEqual(state.status, "runtime_mismatch")
        self.assertTrue(state.proxy_active)
        self.assertIn("owned_listener:tcp/2080", state.runtime_artifacts)

    def test_status_returns_connected_when_process_alive(self) -> None:
        process = unittest.mock.Mock()
        process.poll.return_value = None
        self.driver._process = process
        self.driver._active_profile = self.profile
        self.driver._connected_at = unittest.mock.sentinel.connected_at

        state = self._status()
        self.assertEqual(state.status, "connected")
        self.assertEqual(state.active_profile_id, "vless-1")
        self.assertIs(state.connected_at, unittest.mock.sentinel.connected_at)
        self.assertTrue(state.proxy_active)
        self.assertFalse(state.tun_active)

    def test_status_reports_missing_proxy_listener_as_critical_mismatch(self) -> None:
        process = unittest.mock.Mock()
        process.poll.return_value = None
        self.driver._process = process
        self.driver._active_profile = self.profile

        state = self._status(ports=(2080,))

        self.assertEqual(state.status, "runtime_mismatch")
        self.assertFalse(state.proxy_active)
        self.assertIn("missing_proxy_listener:tcp/2081", state.runtime_artifacts)

    def test_status_rejects_foreign_proxy_listeners_for_live_process(self) -> None:
        process = unittest.mock.Mock()
        process.poll.return_value = None
        self.driver._process = process
        self.driver._active_profile = self.profile

        state = self._status(ports=())

        self.assertEqual(state.status, "runtime_mismatch")
        self.assertFalse(state.proxy_active)
        self.assertIn("missing_proxy_listener:tcp/2080", state.runtime_artifacts)
        self.assertIn("missing_proxy_listener:tcp/2081", state.runtime_artifacts)

    @patch.object(SingBoxDriver, "_tun_interface_active", return_value=True)
    def test_status_reports_unexpected_tun_routing_in_proxy_mode(self, tun_mock) -> None:
        process = unittest.mock.Mock()
        process.poll.return_value = None
        self.driver._process = process
        self.driver._active_profile = self.profile

        state = self._status(
            nft_observation=(True, True),
            residue=(("9000",), ("2022",)),
        )

        self.assertEqual(state.status, "runtime_mismatch")
        self.assertIn("unexpected_tun_interface:wdvpn-tun0", state.runtime_artifacts)
        self.assertIn("unexpected_routing:nft/sing-box", state.runtime_artifacts)

    def test_status_reports_active_lan_gateway(self) -> None:
        process = unittest.mock.Mock()
        process.poll.return_value = None
        self.driver._process = process
        self.driver._active_profile = self.profile
        self.driver._lan_gateway_active = LANGatewayRuntimeConfig(
            lan_interface="enp0s8",
            client_cidr="192.168.50.0/24",
            dns_mode="manual",
        )

        state = self._status()

        self.assertTrue(state.lan_gateway_active)
        self.assertEqual(state.lan_gateway_interface, "enp0s8")
        self.assertEqual(state.lan_gateway_client_cidr, "192.168.50.0/24")
        self.assertEqual(state.lan_gateway_dns_mode, "manual")
        self.assertEqual(state.lan_gateway_status, "degraded")

    @patch.object(SingBoxDriver, "_tun_interface_active", return_value=True)
    def test_status_reports_applied_lan_gateway_when_tun_is_active(self, tun_mock) -> None:
        process = unittest.mock.Mock()
        process.poll.return_value = None
        self.driver._process = process
        self.driver._active_profile = self.profile
        self.driver._tun_expected = True
        self.driver._lan_gateway_active = LANGatewayRuntimeConfig(
            lan_interface="enp0s8",
            client_cidr="192.168.50.0/24",
            dns_mode="manual",
        )

        state = self._status()

        self.assertTrue(state.lan_gateway_active)
        self.assertEqual(state.lan_gateway_status, "applied")

    @patch.object(SingBoxDriver, "_tun_interface_active", return_value=True)
    def test_status_reports_local_proxy_active_with_tun_capture(self, tun_mock) -> None:
        process = unittest.mock.Mock()
        process.poll.return_value = None
        self.driver._process = process
        self.driver._active_profile = self.profile
        self.driver._active_mode = "tun"
        self.driver._tun_expected = True

        state = self._status()

        self.assertEqual(state.status, "connected")
        self.assertTrue(state.tun_active)
        self.assertTrue(state.proxy_active)

    @patch.object(SingBoxDriver, "_tun_interface_active", return_value=True)
    def test_status_reports_tun_active_for_rules_app_policy(self, tun_mock) -> None:
        process = unittest.mock.Mock()
        process.poll.return_value = None
        self.driver._process = process
        self.driver._active_profile = self.profile
        self.driver._active_mode = "rules"
        self.driver._tun_expected = True

        state = self._status()

        self.assertEqual(state.status, "connected")
        self.assertTrue(state.tun_active)
        self.assertTrue(state.proxy_active)

    def test_status_returns_standby_when_process_dead(self) -> None:
        process = unittest.mock.Mock()
        process.poll.return_value = 1
        self.driver._process = process

        state = self._status()
        self.assertEqual(state.status, "standby")

    @patch.object(SingBoxDriver, "_cleanup_tun_residue")
    @patch.object(SingBoxDriver, "_cleanup_runtime")
    def test_status_reports_residue_without_cleanup_when_child_crashed(
        self, cleanup_mock, tun_cleanup_mock
    ) -> None:
        process = unittest.mock.Mock()
        process.poll.return_value = -9
        self.driver._process = process
        self.driver._active_profile = self.profile
        self.driver._connected_at = unittest.mock.sentinel.connected_at
        self.driver._active_mode = "tun"
        self.driver._tun_expected = True

        state = self._status()

        self.assertEqual(state.status, "runtime_mismatch")
        tun_cleanup_mock.assert_not_called()
        cleanup_mock.assert_not_called()
        self.assertIs(self.driver._process, process)
        self.assertIs(self.driver._active_profile, self.profile)
        self.assertIs(self.driver._connected_at, unittest.mock.sentinel.connected_at)
        self.assertEqual(self.driver._active_mode, "tun")
        self.assertTrue(self.driver._tun_expected)


class SingBoxDriverManagementRouteInterfaceTests(unittest.TestCase):
    """Regression coverage for the R28-006 post-merge finding: WatchdogVPN's
    own native-driver interface names must never be classified as a physical
    management route by the SSH-preservation preflight."""

    def setUp(self) -> None:
        self.driver = SingBoxDriver()

    def test_is_physical_interface_rejects_wd_prefixed_owned_names(self) -> None:
        # These three follow the "wd"-prefix convention, so the prefix rule
        # alone must reject them. watchdogvpn_awg does not (it starts with
        # "wa", not "wd") and is deliberately covered separately by the
        # known_owned_interfaces exact-match layer, tested below.
        owned_names = (
            "wdtun7f3a2b1c9d",
            "wdtap7f3a2b1c9d",
            "wdvpn-tun0",
        )
        for name in owned_names:
            with self.subTest(name=name):
                self.assertFalse(self.driver._is_physical_interface(name))

    def test_is_physical_interface_does_not_recognize_amneziawg_name_by_prefix(
        self,
    ) -> None:
        # Documents why the exact-match known_owned_interfaces layer is
        # required in addition to the prefix rule: watchdogvpn_awg's naming
        # convention does not share the "wd" prefix used elsewhere.
        self.assertTrue(self.driver._is_physical_interface("watchdogvpn_awg"))

    def test_is_physical_interface_accepts_real_hardware_names(self) -> None:
        for name in ("enp0s8", "eth0", "wlan0"):
            with self.subTest(name=name):
                self.assertTrue(self.driver._is_physical_interface(name))

    def test_preflight_native_management_routes_refuses_owned_interface_by_prefix(
        self,
    ) -> None:
        # wdtun<token>/wdtap<token> are OpenVPN/OpenVPN+Cloak's per-connection
        # interface names generated after this preflight runs, so they can
        # never be listed in known_owned_interfaces ahead of time; the "wd"
        # prefix rule is what has to catch them.
        with (
            patch.object(
                SingBoxDriver,
                "_active_ssh_management_peers",
                return_value=("198.51.100.9",),
            ),
            patch(
                "drivers.singbox_driver.subprocess.run",
                return_value=unittest.mock.Mock(
                    returncode=0, stdout="198.51.100.9 dev wdtun7f3a2b1c9d src 10.0.2.15\n"
                ),
            ),
        ):
            with self.assertRaises(ManagementPathSafetyError):
                self.driver.preflight_native_management_routes(
                    mode="tun", capture_modes=("tun",)
                )

    def test_preflight_native_management_routes_refuses_known_owned_interface(self) -> None:
        with (
            patch.object(
                SingBoxDriver,
                "_active_ssh_management_peers",
                return_value=("198.51.100.9",),
            ),
            patch(
                "drivers.singbox_driver.subprocess.run",
                return_value=unittest.mock.Mock(
                    returncode=0, stdout="198.51.100.9 dev watchdogvpn_awg src 10.0.2.15\n"
                ),
            ),
        ):
            with self.assertRaises(ManagementPathSafetyError):
                self.driver.preflight_native_management_routes(
                    mode="tun",
                    capture_modes=("tun",),
                    known_owned_interfaces=("watchdogvpn_awg", "wdvpn-tun0"),
                )

    def test_preflight_native_management_routes_accepts_physical_interface(self) -> None:
        with (
            patch.object(
                SingBoxDriver,
                "_active_ssh_management_peers",
                return_value=("198.51.100.9",),
            ),
            patch(
                "drivers.singbox_driver.subprocess.run",
                return_value=unittest.mock.Mock(
                    returncode=0, stdout="198.51.100.9 dev enp0s8 src 192.168.0.103\n"
                ),
            ),
        ):
            routes = self.driver.preflight_native_management_routes(
                mode="tun",
                capture_modes=("tun",),
                known_owned_interfaces=("watchdogvpn_awg", "wdvpn-tun0"),
            )

        self.assertEqual(routes, {"198.51.100.9": "enp0s8"})


class SingBoxDriverHealthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.driver = SingBoxDriver()
        self.process = unittest.mock.Mock()
        self.process.poll.return_value = None
        self.driver._process = self.process

    @patch.object(SingBoxDriver, "_owned_proxy_egress_ready", return_value=True)
    @patch.object(SingBoxDriver, "_wait_for_proxy_port", return_value=True)
    def test_health_check_ok_requires_owned_proxy_listeners(
        self, port_mock, ownership_mock
    ) -> None:
        self.assertEqual(self.driver.health_check(), "ok")
        port_mock.assert_called_once_with()
        ownership_mock.assert_called_once_with()

    @patch.object(SingBoxDriver, "_owned_proxy_egress_ready", return_value=False)
    @patch.object(SingBoxDriver, "_wait_for_proxy_port", return_value=True)
    def test_health_check_degraded_for_proxy_mode_when_listener_is_foreign(
        self, port_mock, ownership_mock
    ) -> None:
        self.assertEqual(self.driver.health_check(), "degraded")
        port_mock.assert_called_once_with()
        ownership_mock.assert_called_once_with()

    @patch.object(SingBoxDriver, "_owned_proxy_egress_ready", return_value=True)
    @patch.object(SingBoxDriver, "_wait_for_tun_auto_redirect_ready", return_value=True)
    @patch.object(SingBoxDriver, "_wait_for_tun_interface", return_value=True)
    @patch.object(SingBoxDriver, "_wait_for_proxy_port", return_value=True)
    def test_health_check_ok_for_tun_mode_requires_owned_runtime(
        self, port_mock, tun_mock, nft_mock, ownership_mock
    ) -> None:
        self.driver._tun_expected = True
        self.assertEqual(self.driver.health_check(), "ok")
        ownership_mock.assert_called_once_with()

    @patch.object(SingBoxDriver, "_owned_proxy_egress_ready", return_value=False)
    @patch.object(SingBoxDriver, "_wait_for_tun_auto_redirect_ready", return_value=True)
    @patch.object(SingBoxDriver, "_wait_for_tun_interface", return_value=True)
    @patch.object(SingBoxDriver, "_wait_for_proxy_port", return_value=True)
    def test_health_check_degraded_for_tun_when_listener_is_not_owned(
        self, port_mock, tun_mock, nft_mock, ownership_mock
    ) -> None:
        self.driver._tun_expected = True
        self.assertEqual(self.driver.health_check(), "degraded")
        ownership_mock.assert_called_once_with()

    @patch.object(
        SingBoxDriver,
        "_owned_proxy_runtime_observation",
        return_value=((OwnedProcess(pid=42, executable="sing-box"),), TCPListenerObservation(True, (2080, 2081))),
    )
    def test_owned_proxy_egress_requires_observable_owned_listeners(self, observation_mock) -> None:
        self.assertTrue(self.driver._owned_proxy_egress_ready())
        observation_mock.assert_called_once_with()

    @patch.object(
        SingBoxDriver,
        "_owned_proxy_runtime_observation",
        return_value=((OwnedProcess(pid=42, executable="sing-box"),), TCPListenerObservation(False, (2080, 2081))),
    )
    def test_owned_proxy_egress_rejects_unobservable_listener_evidence(self, observation_mock) -> None:
        self.assertFalse(self.driver._owned_proxy_egress_ready())
        observation_mock.assert_called_once_with()

    @patch.object(SingBoxDriver, "_wait_for_tun_interface", return_value=False)
    @patch.object(SingBoxDriver, "_wait_for_proxy_port", return_value=True)
    def test_health_check_degraded_when_tun_interface_missing(self, port_mock, tun_mock) -> None:
        self.driver._tun_expected = True
        self.assertEqual(self.driver.health_check(), "degraded")

    @patch.object(SingBoxDriver, "_wait_for_tun_auto_redirect_ready", return_value=False)
    @patch.object(SingBoxDriver, "_wait_for_tun_interface", return_value=True)
    @patch.object(SingBoxDriver, "_wait_for_proxy_port", return_value=True)
    def test_health_check_degraded_when_tun_auto_redirect_not_ready(
        self, port_mock, tun_mock, nft_mock
    ) -> None:
        self.driver._tun_expected = True
        self.assertEqual(self.driver.health_check(), "degraded")

    @patch.object(SingBoxDriver, "_wait_for_proxy_port", return_value=False)
    def test_health_check_degraded_when_ports_closed(self, port_mock) -> None:
        self.assertEqual(self.driver.health_check(), "degraded")

    def test_health_check_down_when_process_missing(self) -> None:
        self.driver._process = None
        self.assertEqual(self.driver.health_check(), "down")

    def test_health_check_down_when_process_dead(self) -> None:
        self.process.poll.return_value = 1
        self.assertEqual(self.driver.health_check(), "down")



if __name__ == "__main__":
    unittest.main()
