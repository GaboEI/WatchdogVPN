from __future__ import annotations

import unittest
from unittest.mock import patch

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

    def connect(self, profile: Profile) -> bool:
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
            return True, "1.2.3.4"

        result = health_checker.check(make_profile(), driver, verify=verify)

        self.assertEqual(result, "down")
        self.assertEqual(verify_calls, [])

    def test_returns_down_when_no_active_route(self) -> None:
        driver = StubDriver("ok", ConnectionState(status="connected", proxy_active=False, tun_active=False))

        result = health_checker.check(
            make_profile(),
            driver,
            verify=lambda via_proxy: (True, "1.2.3.4"),
        )

        self.assertEqual(result, "down")

    def test_ok_when_proxy_active_and_reachable(self) -> None:
        driver = StubDriver("ok", ConnectionState(status="connected", proxy_active=True, tun_active=True))
        verify_calls: list[bool] = []

        def verify(via_proxy: bool):
            verify_calls.append(via_proxy)
            return True, "1.2.3.4"

        result = health_checker.check(make_profile(), driver, verify=verify)

        self.assertEqual(result, "ok")
        self.assertEqual(verify_calls, [True])

    def test_ok_when_tun_active_without_proxy(self) -> None:
        driver = StubDriver("ok", ConnectionState(status="connected", proxy_active=False, tun_active=True))
        verify_calls: list[bool] = []

        def verify(via_proxy: bool):
            verify_calls.append(via_proxy)
            return True, "5.6.7.8"

        result = health_checker.check(make_profile(), driver, verify=verify)

        self.assertEqual(result, "ok")
        self.assertEqual(verify_calls, [False])

    def test_degraded_when_external_endpoint_unreachable(self) -> None:
        driver = StubDriver("ok", ConnectionState(status="connected", proxy_active=True, tun_active=True))

        result = health_checker.check(
            make_profile(),
            driver,
            verify=lambda via_proxy: (False, None),
        )

        self.assertEqual(result, "degraded")

    def test_degraded_is_sticky_even_if_reachable(self) -> None:
        driver = StubDriver("degraded", ConnectionState(status="connected", proxy_active=True, tun_active=True))

        result = health_checker.check(
            make_profile(),
            driver,
            verify=lambda via_proxy: (True, "1.2.3.4"),
        )

        self.assertEqual(result, "degraded")

    def test_ok_even_when_public_ip_lookup_fails(self) -> None:
        driver = StubDriver("ok", ConnectionState(status="connected", proxy_active=True, tun_active=True))

        result = health_checker.check(
            make_profile(),
            driver,
            verify=lambda via_proxy: (True, None),
        )

        self.assertEqual(result, "ok")


class ReachableAndPublicIpTests(unittest.TestCase):
    @patch("rotation.health_checker.shutil.which", return_value=None)
    def test_returns_false_when_curl_not_found(self, _which) -> None:
        reachable, public_ip = health_checker.reachable_and_public_ip(via_proxy=False)

        self.assertFalse(reachable)
        self.assertIsNone(public_ip)

    @patch("rotation.health_checker.subprocess.run")
    @patch("rotation.health_checker.shutil.which", return_value="/usr/bin/curl")
    def test_uses_socks_proxy_args_when_via_proxy(self, _which, run_mock) -> None:
        run_mock.return_value.returncode = 0
        run_mock.return_value.stdout = "203.0.113.5"

        reachable, public_ip = health_checker.reachable_and_public_ip(via_proxy=True)

        self.assertTrue(reachable)
        self.assertEqual(public_ip, "203.0.113.5")
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

        reachable, public_ip = health_checker.reachable_and_public_ip(via_proxy=False)

        self.assertFalse(reachable)
        self.assertIsNone(public_ip)
        run_mock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
