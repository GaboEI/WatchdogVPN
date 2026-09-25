from __future__ import annotations

import unittest
from unittest.mock import Mock

from drivers.native_policy_driver import KNOWN_OWNED_INTERFACES, NativePolicyDriver
from drivers.singbox_driver import SingBoxDriver
from models.connection_state import ConnectionState
from models.profile import Profile, ProfileSource, ProtocolType


class NativePolicyDriverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = Profile(
            "native", "native", ProtocolType.AMNEZIAWG,
            {"host": "198.51.100.7"}, ProfileSource.MANUAL,
        )
        self.native = Mock()
        self.native.connect.return_value = True
        self.native.health_check.return_value = "ok"
        self.native.disconnect.return_value = True
        self.native.status.return_value = ConnectionState(active_profile_id="native", status="connected")
        self.native.egress_interface.return_value = "watchdogvpn_awg"
        self.native.is_available.return_value = True
        self.companion = Mock(spec=SingBoxDriver)
        self.companion.connect.return_value = True
        self.companion.preflight_native_management_routes.return_value = {}
        self.companion.health_check.return_value = "ok"
        self.companion.disconnect.return_value = True
        self.companion.status.return_value = ConnectionState(tun_active=True, proxy_active=True, status="connected")
        self.companion.is_available.return_value = True
        self.driver = NativePolicyDriver(self.native, self.companion)

    def test_companion_failure_rolls_back_native_transport(self) -> None:
        self.companion.connect.return_value = False
        self.companion.last_error = "companion failed"

        self.assertFalse(self.driver.connect(self.profile, mode="rules"))
        self.native.connect.assert_called_once_with(self.profile)
        self.companion.connect.assert_called_once_with(
            self.profile, dns_policy=None, mode="rules", native_transport=True,
            native_bypass_cidrs=("198.51.100.7/32",), management_peers=(),
            native_egress_interface="watchdogvpn_awg",
        )
        self.companion.disconnect.assert_called_once_with()
        self.native.disconnect.assert_called_once_with()
        self.assertEqual(self.driver.status().status, "standby")

    def test_connect_passes_known_owned_interfaces_to_preflight(self) -> None:
        self.assertTrue(self.driver.connect(self.profile, mode="tun", capture_modes=("tun",)))

        self.companion.preflight_native_management_routes.assert_called_once_with(
            mode="tun", capture_modes=("tun",), known_owned_interfaces=KNOWN_OWNED_INTERFACES,
        )

    def test_connected_status_requires_both_owners(self) -> None:
        self.assertTrue(self.driver.connect(self.profile, mode="rules"))
        state = self.driver.status()
        self.assertEqual(state.status, "connected")
        self.assertTrue(state.tun_active)
        self.assertTrue(state.proxy_active)

    def test_disconnect_stops_companion_before_native(self) -> None:
        calls = []
        self.companion.disconnect.side_effect = lambda: calls.append("companion") or True
        self.native.disconnect.side_effect = lambda: calls.append("native") or True
        self.assertTrue(self.driver.connect(self.profile))
        self.assertTrue(self.driver.disconnect())
        self.assertEqual(calls[-2:], ["companion", "native"])

    def test_connect_fails_closed_without_native_egress_interface(self) -> None:
        self.native.egress_interface.return_value = None

        self.assertFalse(self.driver.connect(self.profile, mode="tun"))

        self.companion.connect.assert_not_called()
        self.native.disconnect.assert_called_once_with()
        self.assertEqual(self.driver.last_error, "native transport egress interface is unavailable")

    def test_native_preflight_runs_before_existing_runtime_teardown(self) -> None:
        self.native.preflight_profile.side_effect = ValueError("invalid raw remote")
        self.driver._active_profile = self.profile

        self.assertFalse(self.driver.connect(self.profile, mode="rules"))

        self.native.disconnect.assert_not_called()
        self.companion.disconnect.assert_not_called()
        self.native.connect.assert_not_called()
        self.companion.connect.assert_not_called()
        self.assertEqual(self.driver.last_error, "invalid raw remote")


class NativeEndpointBypassCidrsTests(unittest.TestCase):
    """Regression coverage for a real-VM finding: every profile actually
    produced by parsers/wg_config.py and parsers/amneziavpn_format.py stores
    the peer address under config["endpoint"] as "host:port" (WireGuard's
    own Endpoint= syntax), never under "host"/"server". This function only
    ever checked "host"/"server", so it silently returned an empty tuple for
    every real WireGuard/AmneziaWG profile - the companion's TUN then had
    nothing to exclude from auto_route, and the native transport's own raw
    UDP packets to its own server got captured into the tunnel it belonged
    to, a few seconds after the interface came up."""

    def _profile(self, config: dict) -> Profile:
        return Profile("native", "native", ProtocolType.AMNEZIAWG, config, ProfileSource.MANUAL)

    def test_falls_back_to_endpoint_key_stripping_the_port(self) -> None:
        profile = self._profile({"endpoint": "198.51.100.7:51820"})
        cidrs = NativePolicyDriver._native_endpoint_bypass_cidrs(profile)
        self.assertEqual(cidrs, ("198.51.100.7/32",))

    def test_endpoint_key_handles_bracketed_ipv6_with_port(self) -> None:
        profile = self._profile({"endpoint": "[2001:db8::1]:51820"})
        cidrs = NativePolicyDriver._native_endpoint_bypass_cidrs(profile)
        self.assertEqual(cidrs, ("2001:db8::1/128",))

    def test_host_key_still_takes_priority_over_endpoint(self) -> None:
        profile = self._profile(
            {"host": "198.51.100.9", "endpoint": "198.51.100.7:51820"}
        )
        cidrs = NativePolicyDriver._native_endpoint_bypass_cidrs(profile)
        self.assertEqual(cidrs, ("198.51.100.9/32",))

    def test_returns_empty_when_neither_key_is_present(self) -> None:
        profile = self._profile({})
        cidrs = NativePolicyDriver._native_endpoint_bypass_cidrs(profile)
        self.assertEqual(cidrs, ())

    def test_connect_threads_endpoint_derived_cidrs_into_companion(self) -> None:
        # End-to-end: the realistic profile shape (endpoint, not host) must
        # actually reach preflight_native_management_routes's
        # known_owned_interfaces sibling parameter on companion.connect().
        native = Mock()
        native.connect.return_value = True
        native.status.return_value = ConnectionState(active_profile_id="native", status="connected")
        native.egress_interface.return_value = "watchdogvpn_awg"
        companion = Mock(spec=SingBoxDriver)
        companion.connect.return_value = True
        companion.preflight_native_management_routes.return_value = {}
        companion.health_check.return_value = "ok"
        driver = NativePolicyDriver(native, companion)
        profile = self._profile({"endpoint": "198.51.100.7:51820"})

        self.assertTrue(driver.connect(profile, mode="rules"))

        companion.connect.assert_called_once()
        self.assertEqual(
            companion.connect.call_args.kwargs["native_bypass_cidrs"],
            ("198.51.100.7/32",),
        )
        self.assertEqual(
            companion.connect.call_args.kwargs["native_egress_interface"],
            "watchdogvpn_awg",
        )

    def test_openvpn_bypass_cidr_uses_raw_config_remote_not_host_metadata(self) -> None:
        profile = Profile(
            "openvpn-native",
            "openvpn-native",
            ProtocolType.OPENVPN,
            {"host": "138.124.91.224", "raw_config": "client\nremote 8.8.8.8 1194\n"},
            ProfileSource.MANUAL,
        )

        cidrs = NativePolicyDriver._native_endpoint_bypass_cidrs(profile)

        self.assertEqual(cidrs, ("8.8.8.8/32",))


if __name__ == "__main__":
    unittest.main()
