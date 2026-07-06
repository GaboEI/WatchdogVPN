from __future__ import annotations

import unittest
from unittest.mock import patch

from dns.models import DNSPolicy
from drivers.base import BaseDriver
from models.connection_state import ConnectionState
from models.profile import Profile, ProfileSource, ProtocolType
from rotation import health_checker


def make_profile(profile_id: str = "p1") -> Profile:
    return Profile(
        id=profile_id,
        name=profile_id,
        protocol=ProtocolType.VLESS,
        config={},
        source=ProfileSource.MANUAL,
    )


class StubDriver(BaseDriver):
    def __init__(self, health: str, state: ConnectionState) -> None:
        self.health = health
        self.state = state
        self.health_check_calls = 0

    def connect(
        self,
        profile: Profile,
        dns_policy: DNSPolicy | None = None,
        *,
        mode: str = "global",
        groups=None,
        app_policy=None,
        final_policy: str = "current_profile",
    ) -> bool:
        return True

    def disconnect(self) -> bool:
        return True

    def health_check(self) -> str:
        self.health_check_calls += 1
        return self.health

    def status(self) -> ConnectionState:
        return self.state

    def is_available(self) -> bool:
        return True


class HealthCheckerTests(unittest.TestCase):
    def test_returns_down_immediately_when_driver_reports_down(self) -> None:
        driver = StubDriver("down", ConnectionState(status="standby"))
        verify_calls: list[bool] = []

        def verify(via_proxy: bool):
            verify_calls.append(via_proxy)
            return True, "1.2.3.4", 42.0

        result = health_checker.check(make_profile(), driver, verify=verify)

        self.assertEqual(result, "down")
        self.assertEqual(verify_calls, [])

    def test_returns_down_when_no_active_route(self) -> None:
        driver = StubDriver("ok", ConnectionState(status="connected", proxy_active=False, tun_active=False))

        result = health_checker.check(
            make_profile(),
            driver,
            verify=lambda via_proxy: (True, "1.2.3.4", 42.0),
        )

        self.assertEqual(result, "down")

    def test_ok_when_proxy_active_and_reachable(self) -> None:
        driver = StubDriver(
            "ok",
            ConnectionState(status="connected", mode="sing-box", proxy_active=True, tun_active=True),
        )
        verify_calls: list[bool] = []

        def verify(via_proxy: bool):
            verify_calls.append(via_proxy)
            return True, "1.2.3.4", 42.0

        result = health_checker.check(make_profile(), driver, verify=verify)

        self.assertEqual(result, "ok")
        self.assertEqual(verify_calls, [True])

    def test_ok_when_tun_active_without_proxy(self) -> None:
        driver = StubDriver(
            "ok",
            ConnectionState(status="connected", mode="amneziawg", proxy_active=False, tun_active=True),
        )
        verify_calls: list[bool] = []

        def verify(via_proxy: bool):
            verify_calls.append(via_proxy)
            return True, "5.6.7.8", 42.0

        result = health_checker.check(make_profile(), driver, verify=verify)

        self.assertEqual(result, "ok")
        self.assertEqual(verify_calls, [False])

    def test_uses_direct_verification_for_non_singbox_mode_even_if_proxy_active_flag_is_set(self) -> None:
        # Regression: a non-sing-box driver could in principle set
        # proxy_active=True to mean "VPN is up" rather than "a local SOCKS
        # proxy is listening" - only mode == "sing-box" should trigger
        # proxy-based verification.
        driver = StubDriver(
            "ok",
            ConnectionState(status="connected", mode="openvpn", proxy_active=True, tun_active=True),
        )
        verify_calls: list[bool] = []

        def verify(via_proxy: bool):
            verify_calls.append(via_proxy)
            return True, "9.9.9.9", 42.0

        result = health_checker.check(make_profile(), driver, verify=verify)

        self.assertEqual(result, "ok")
        self.assertEqual(verify_calls, [False])

    def test_falls_back_to_direct_when_proxy_mode_driver_has_proxy_inactive(self) -> None:
        # Regression: a driver whose mode IS in PROXY_BASED_MODES but is
        # currently running without the local proxy up (proxy_active=False)
        # - e.g. a future sing-box TUN connection mode (Phase 11) - must
        # still fall through to direct/TUN verification instead of being
        # short-circuited to "down".
        driver = StubDriver(
            "ok",
            ConnectionState(status="connected", mode="sing-box", proxy_active=False, tun_active=True),
        )
        verify_calls: list[bool] = []

        def verify(via_proxy: bool):
            verify_calls.append(via_proxy)
            return True, "8.8.4.4", 42.0

        result = health_checker.check(make_profile(), driver, verify=verify)

        self.assertEqual(result, "ok")
        self.assertEqual(verify_calls, [False])

    def test_degraded_when_external_endpoint_unreachable(self) -> None:
        driver = StubDriver(
            "ok",
            ConnectionState(status="connected", mode="sing-box", proxy_active=True, tun_active=True),
        )

        result = health_checker.check(
            make_profile(),
            driver,
            verify=lambda via_proxy: (False, None, None),
        )

        self.assertEqual(result, "degraded")

    def test_degraded_is_sticky_even_if_reachable(self) -> None:
        driver = StubDriver(
            "degraded",
            ConnectionState(status="connected", mode="sing-box", proxy_active=True, tun_active=True),
        )

        result = health_checker.check(
            make_profile(),
            driver,
            verify=lambda via_proxy: (True, "1.2.3.4", 42.0),
        )

        self.assertEqual(result, "degraded")

    def test_ok_even_when_public_ip_lookup_fails(self) -> None:
        driver = StubDriver(
            "ok",
            ConnectionState(status="connected", mode="sing-box", proxy_active=True, tun_active=True),
        )

        result = health_checker.check(
            make_profile(),
            driver,
            verify=lambda via_proxy: (True, None, 42.0),
        )

        self.assertEqual(result, "ok")


class CheckWithLatencyTests(unittest.TestCase):
    """check_with_latency() reuses check()'s exact logic (_check_full) -
    these pin that the richer HealthCheckResult is available without
    changing check()'s own str-returning contract (RotationEngine's
    HealthCheckFn depends on that contract and must never see this type)."""

    def test_ok_result_carries_latency(self) -> None:
        driver = StubDriver(
            "ok",
            ConnectionState(status="connected", mode="sing-box", proxy_active=True, tun_active=True),
        )

        result = health_checker.check_with_latency(
            make_profile(),
            driver,
            verify=lambda via_proxy: (True, "1.2.3.4", 123.456),
        )

        self.assertEqual(result.status, "ok")
        self.assertEqual(result.latency_ms, 123.456)

    def test_down_result_has_no_latency(self) -> None:
        driver = StubDriver("down", ConnectionState(status="standby"))

        result = health_checker.check_with_latency(
            make_profile(), driver, verify=lambda via_proxy: (True, "1.2.3.4", 42.0)
        )

        self.assertEqual(result.status, "down")
        self.assertIsNone(result.latency_ms)

    def test_unreachable_result_has_no_latency(self) -> None:
        driver = StubDriver(
            "ok",
            ConnectionState(status="connected", mode="sing-box", proxy_active=True, tun_active=True),
        )

        result = health_checker.check_with_latency(
            make_profile(), driver, verify=lambda via_proxy: (False, None, None)
        )

        self.assertEqual(result.status, "degraded")
        self.assertIsNone(result.latency_ms)

    def test_degraded_driver_status_still_carries_latency(self) -> None:
        driver = StubDriver(
            "degraded",
            ConnectionState(status="connected", mode="sing-box", proxy_active=True, tun_active=True),
        )

        result = health_checker.check_with_latency(
            make_profile(), driver, verify=lambda via_proxy: (True, "1.2.3.4", 77.0)
        )

        self.assertEqual(result.status, "degraded")
        self.assertEqual(result.latency_ms, 77.0)

    def test_check_and_check_with_latency_agree_on_status(self) -> None:
        driver = StubDriver(
            "ok",
            ConnectionState(status="connected", mode="sing-box", proxy_active=True, tun_active=True),
        )
        verify = lambda via_proxy: (True, "1.2.3.4", 10.0)

        self.assertEqual(
            health_checker.check(make_profile(), driver, verify=verify),
            health_checker.check_with_latency(make_profile(), driver, verify=verify).status,
        )


class ReachableAndPublicIpTests(unittest.TestCase):
    @patch("rotation.health_checker.shutil.which", return_value=None)
    def test_returns_false_when_curl_not_found(self, _which) -> None:
        reachable, public_ip, latency_ms = health_checker.reachable_and_public_ip(via_proxy=False)

        self.assertFalse(reachable)
        self.assertIsNone(public_ip)
        self.assertIsNone(latency_ms)

    @patch("rotation.health_checker.subprocess.run")
    @patch("rotation.health_checker.shutil.which", return_value="/usr/bin/curl")
    def test_uses_socks_proxy_args_when_via_proxy(self, _which, run_mock) -> None:
        run_mock.return_value.returncode = 0
        run_mock.return_value.stdout = "203.0.113.5"

        reachable, public_ip, latency_ms = health_checker.reachable_and_public_ip(via_proxy=True)

        self.assertTrue(reachable)
        self.assertEqual(public_ip, "203.0.113.5")
        self.assertIsInstance(latency_ms, float)
        self.assertGreaterEqual(latency_ms, 0.0)
        first_call_args = run_mock.call_args_list[0].args[0]
        self.assertIn("--socks5-hostname", first_call_args)
        self.assertIn(health_checker.LOCAL_SOCKS_PROXY, first_call_args)

    @patch("rotation.health_checker.subprocess.run")
    @patch("rotation.health_checker.shutil.which", return_value="/usr/bin/curl")
    def test_no_proxy_args_when_direct(self, _which, run_mock) -> None:
        run_mock.return_value.returncode = 0
        run_mock.return_value.stdout = "203.0.113.5"

        health_checker.reachable_and_public_ip(via_proxy=False)

        first_call_args = run_mock.call_args_list[0].args[0]
        self.assertNotIn("--socks5-hostname", first_call_args)

    @patch("rotation.health_checker.subprocess.run")
    @patch("rotation.health_checker.shutil.which", return_value="/usr/bin/curl")
    def test_reachable_false_when_external_check_fails(self, _which, run_mock) -> None:
        run_mock.return_value.returncode = 1
        run_mock.return_value.stdout = ""

        reachable, public_ip, latency_ms = health_checker.reachable_and_public_ip(via_proxy=False)

        self.assertFalse(reachable)
        self.assertIsNone(public_ip)
        self.assertIsNone(latency_ms)
        run_mock.assert_called_once()

    @patch("rotation.health_checker.subprocess.run")
    @patch("rotation.health_checker.shutil.which", return_value="/usr/bin/curl")
    def test_uses_the_configured_test_url_not_the_module_default(self, _which, run_mock) -> None:
        run_mock.return_value.returncode = 0
        run_mock.return_value.stdout = "203.0.113.5"

        health_checker.reachable_and_public_ip(via_proxy=False, test_url="https://custom.example/test")

        first_call_args = run_mock.call_args_list[0].args[0]
        self.assertIn("https://custom.example/test", first_call_args)
        self.assertNotIn(health_checker.EXTERNAL_CHECK_URL, first_call_args)


if __name__ == "__main__":
    unittest.main()
