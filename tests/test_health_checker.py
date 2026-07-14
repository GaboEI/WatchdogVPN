from __future__ import annotations

import json
import subprocess
from dataclasses import asdict
import unittest
from unittest.mock import Mock, patch

from dns.models import DNSPolicy
from drivers.base import BaseDriver
from models.connection_state import ConnectionState
from models.profile import Profile, ProfileSource, ProtocolType
from rotation import health_checker
from rotation.health_targets import HealthProbeResult, HealthTargetResult, probe_targets


def make_profile(profile_id: str = "p1") -> Profile:
    return Profile(
        id=profile_id,
        name=profile_id,
        protocol=ProtocolType.VLESS,
        config={},
        source=ProfileSource.MANUAL,
    )


def probe(
    *,
    successes: int,
    classification: str = "healthy",
    latency_ms: float | None = 42.0,
) -> HealthProbeResult:
    results = tuple(
        HealthTargetResult(
            target=f"https://target-{index}.example/",
            reachable=index < successes,
            classification="ok" if index < successes else classification,
            curl_exit_code=0 if index < successes else 28,
            latency_ms=latency_ms if index < successes else None,
        )
        for index in range(3)
    )
    return HealthProbeResult(
        targets=results,
        success_count=successes,
        required_successes=2,
        classification="healthy" if successes >= 2 else classification,
        latency_ms=latency_ms if successes else None,
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
    def test_returns_down_without_probe_when_driver_reports_tunnel_failure(self) -> None:
        driver = StubDriver("down", ConnectionState(status="standby"))
        verify = Mock(return_value=probe(successes=3))

        result = health_checker.check_with_latency(make_profile(), driver, verify=verify)

        self.assertEqual(result.status, "down")
        self.assertEqual(result.classification, "tunnel_failure")
        verify.assert_not_called()

    def test_proxy_path_uses_quorum_probe(self) -> None:
        driver = StubDriver(
            "ok",
            ConnectionState(status="connected", mode="sing-box", proxy_active=True, tun_active=True),
        )
        verify = Mock(return_value=probe(successes=2))

        result = health_checker.check_with_latency(make_profile(), driver, verify=verify)

        self.assertEqual(result.status, "ok")
        self.assertEqual(result.latency_ms, 42.0)
        verify.assert_called_once_with(True)

    def test_tun_path_uses_direct_probe(self) -> None:
        driver = StubDriver(
            "ok",
            ConnectionState(status="connected", mode="openvpn", proxy_active=False, tun_active=True),
        )
        verify = Mock(return_value=probe(successes=2))

        self.assertEqual(health_checker.check(make_profile(), driver, verify=verify), "ok")
        verify.assert_called_once_with(False)

    def test_single_blocked_target_with_quorum_is_healthy(self) -> None:
        driver = StubDriver(
            "ok",
            ConnectionState(status="connected", mode="sing-box", proxy_active=True, tun_active=True),
        )

        result = health_checker.check_with_latency(
            make_profile(), driver, verify=lambda _via_proxy: probe(successes=2)
        )

        self.assertEqual(result.status, "ok")
        self.assertEqual(result.classification, "healthy")

    def test_all_target_failure_is_degraded_not_false_success(self) -> None:
        driver = StubDriver(
            "ok",
            ConnectionState(status="connected", mode="sing-box", proxy_active=True, tun_active=True),
        )

        result = health_checker.check_with_latency(
            make_profile(),
            driver,
            verify=lambda _via_proxy: probe(
                successes=0,
                classification="endpoint_censorship_or_network_interference_suspected",
                latency_ms=None,
            ),
        )

        self.assertEqual(result.status, "degraded")
        self.assertEqual(result.classification, "endpoint_censorship_or_network_interference_suspected")

    def test_dns_interference_is_classified_separately(self) -> None:
        driver = StubDriver(
            "ok",
            ConnectionState(status="connected", mode="sing-box", proxy_active=True, tun_active=True),
        )

        result = health_checker.check_with_latency(
            make_profile(),
            driver,
            verify=lambda _via_proxy: probe(
                successes=0,
                classification="dns_interference_suspected",
                latency_ms=None,
            ),
        )

        self.assertEqual(result.status, "degraded")
        self.assertEqual(result.classification, "dns_interference_suspected")

    def test_third_party_outage_is_classified_separately(self) -> None:
        driver = StubDriver(
            "ok",
            ConnectionState(status="connected", mode="sing-box", proxy_active=True, tun_active=True),
        )

        result = health_checker.check_with_latency(
            make_profile(),
            driver,
            verify=lambda _via_proxy: probe(
                successes=0,
                classification="third_party_outage",
                latency_ms=None,
            ),
        )

        self.assertEqual(result.status, "degraded")
        self.assertEqual(result.classification, "third_party_outage")

    def test_degraded_driver_remains_degraded_after_healthy_probe(self) -> None:
        driver = StubDriver(
            "degraded",
            ConnectionState(status="connected", mode="sing-box", proxy_active=True, tun_active=True),
        )

        result = health_checker.check_with_latency(
            make_profile(), driver, verify=lambda _via_proxy: probe(successes=3)
        )

        self.assertEqual(result.status, "degraded")
        self.assertEqual(result.classification, "driver_degraded")

    def test_no_active_route_is_down_without_probe(self) -> None:
        driver = StubDriver("ok", ConnectionState(status="connected", proxy_active=False, tun_active=False))
        verify = Mock(return_value=probe(successes=3))

        result = health_checker.check_with_latency(make_profile(), driver, verify=verify)

        self.assertEqual(result.status, "down")
        self.assertEqual(result.classification, "no_active_route")
        verify.assert_not_called()


def curl_result(returncode: int) -> Mock:
    result = Mock()
    result.returncode = returncode
    return result


class TargetProbeTests(unittest.TestCase):
    TARGETS = (
        "https://one.example/",
        "https://two.example/",
        "https://three.example/",
    )

    @patch("rotation.health_targets.shutil.which", return_value=None)
    def test_missing_curl_is_not_healthy(self, _which) -> None:
        result = probe_targets(via_proxy=False, targets=self.TARGETS, timeout=5, success_quorum=2)

        self.assertFalse(result.reachable)
        self.assertEqual(result.classification, "probe_unavailable")

    @patch("rotation.health_targets.subprocess.run")
    @patch("rotation.health_targets.shutil.which", return_value="/usr/bin/curl")
    def test_uses_remote_dns_through_socks_proxy(self, _which, run_mock) -> None:
        run_mock.side_effect = [curl_result(0), curl_result(0), curl_result(28)]

        result = probe_targets(via_proxy=True, targets=self.TARGETS, timeout=5, success_quorum=2)

        self.assertTrue(result.reachable)
        self.assertEqual(result.success_count, 2)
        first = run_mock.call_args_list[0].args[0]
        self.assertIn("--socks5-hostname", first)
        self.assertIn("127.0.0.1:2080", first)

    @patch("rotation.health_targets.subprocess.run")
    @patch("rotation.health_targets.shutil.which", return_value="/usr/bin/curl")
    def test_single_blocked_target_does_not_fail_healthy_quorum(self, _which, run_mock) -> None:
        run_mock.side_effect = [curl_result(0), curl_result(28), curl_result(0)]

        result = probe_targets(via_proxy=False, targets=self.TARGETS, timeout=5, success_quorum=2)

        self.assertTrue(result.reachable)
        self.assertEqual(result.classification, "healthy")
        self.assertEqual(result.targets[1].classification, "endpoint_censorship_or_network_interference_suspected")

    @patch("rotation.health_targets.subprocess.run")
    @patch("rotation.health_targets.shutil.which", return_value="/usr/bin/curl")
    def test_all_dns_failures_are_classified_without_false_success(self, _which, run_mock) -> None:
        run_mock.side_effect = [curl_result(6), curl_result(6), curl_result(6)]

        result = probe_targets(via_proxy=True, targets=self.TARGETS, timeout=5, success_quorum=2)

        self.assertFalse(result.reachable)
        self.assertEqual(result.classification, "dns_interference_suspected")

    @patch("rotation.health_targets.subprocess.run")
    @patch("rotation.health_targets.shutil.which", return_value="/usr/bin/curl")
    def test_all_service_failures_are_classified_without_false_success(self, _which, run_mock) -> None:
        run_mock.side_effect = [curl_result(22), curl_result(22), curl_result(22)]

        result = probe_targets(via_proxy=False, targets=self.TARGETS, timeout=5, success_quorum=2)

        self.assertFalse(result.reachable)
        self.assertEqual(result.classification, "third_party_outage")



class AutomaticHealthPrivacyTests(unittest.TestCase):
    CANARY_PUBLIC_IP = "203.0.113.77"
    TARGETS = (
        "https://one.example/",
        "https://two.example/",
        "https://three.example/",
    )

    def _curl_result_with_canary(self, returncode: int) -> Mock:
        result = curl_result(returncode)
        result.stdout = f"ip={self.CANARY_PUBLIC_IP}"
        result.stderr = f"diagnostic={self.CANARY_PUBLIC_IP}"
        return result

    @patch("rotation.health_targets.subprocess.run")
    @patch("rotation.health_targets.shutil.which", return_value="/usr/bin/curl")
    def test_automatic_health_discards_raw_curl_payloads_from_results_and_logs(
        self, _which, run_mock
    ) -> None:
        run_mock.side_effect = [
            self._curl_result_with_canary(0),
            self._curl_result_with_canary(0),
            self._curl_result_with_canary(28),
            self._curl_result_with_canary(28),
            self._curl_result_with_canary(28),
            self._curl_result_with_canary(28),
        ]

        healthy = probe_targets(via_proxy=True, targets=self.TARGETS, timeout=5, success_quorum=2)
        failed = probe_targets(via_proxy=True, targets=self.TARGETS, timeout=5, success_quorum=2)
        driver = StubDriver(
            "ok",
            ConnectionState(status="connected", mode="sing-box", proxy_active=True, tun_active=True),
        )
        with self.assertLogs("rotation.health_checker", level="INFO") as captured:
            health_checker.check_with_latency(make_profile(), driver, verify=lambda _via_proxy: healthy)
            health_checker.check_with_latency(make_profile(), driver, verify=lambda _via_proxy: failed)

        retained = json.dumps({"healthy": asdict(healthy), "failed": asdict(failed)}, sort_keys=True)
        self.assertNotIn(self.CANARY_PUBLIC_IP, retained)
        self.assertNotIn(self.CANARY_PUBLIC_IP, "\n".join(captured.output))
        self.assertTrue(
            all(call.kwargs["stderr"] is subprocess.DEVNULL for call in run_mock.call_args_list)
        )
        self.assertTrue(
            all(
                call.args[0][call.args[0].index("--output") + 1] == "/dev/null"
                for call in run_mock.call_args_list
            )
        )


class TargetPolicyValidationTests(unittest.TestCase):
    TARGETS = [
        "https://one.example/",
        "https://two.example/",
        "https://three.example/",
    ]

    def test_accepts_multiple_unique_https_targets(self) -> None:
        from rotation.health_targets import validate_targets

        self.assertEqual(validate_targets(self.TARGETS), tuple(self.TARGETS))

    def test_rejects_a_single_target(self) -> None:
        from rotation.health_targets import validate_targets

        with self.assertRaises(ValueError):
            validate_targets(self.TARGETS[:1])

    def test_rejects_credentials_and_fragments(self) -> None:
        from rotation.health_targets import validate_targets

        for unsafe in ("https://user:secret@one.example/", "https://one.example/#fragment"):
            with self.subTest(unsafe=unsafe):
                with self.assertRaises(ValueError):
                    validate_targets([unsafe, *self.TARGETS[1:]])

    def test_rejects_duplicate_targets(self) -> None:
        from rotation.health_targets import validate_targets

        with self.assertRaises(ValueError):
            validate_targets([self.TARGETS[0], self.TARGETS[0], self.TARGETS[2]])

    def test_rejects_boolean_or_out_of_range_quorum(self) -> None:
        from rotation.health_targets import validate_success_quorum

        for invalid in (True, 0, 4):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    validate_success_quorum(invalid, self.TARGETS)

    @patch("rotation.health_targets.subprocess.run")
    @patch("rotation.health_targets.shutil.which", return_value="/usr/bin/curl")
    def test_one_success_is_insufficient_for_two_target_quorum(self, _which, run_mock) -> None:
        run_mock.side_effect = [curl_result(0), curl_result(28), curl_result(28)]

        result = probe_targets(
            via_proxy=True,
            targets=tuple(self.TARGETS),
            timeout=5,
            success_quorum=2,
        )

        self.assertFalse(result.reachable)
        self.assertEqual(result.classification, "insufficient_target_quorum")

    @patch("rotation.health_targets.subprocess.run")
    @patch("rotation.health_targets.shutil.which", return_value="/usr/bin/curl")
    def test_mixed_all_target_failures_are_not_misattributed_to_one_cause(self, _which, run_mock) -> None:
        run_mock.side_effect = [curl_result(6), curl_result(22), curl_result(28)]

        result = probe_targets(
            via_proxy=True,
            targets=tuple(self.TARGETS),
            timeout=5,
            success_quorum=2,
        )

        self.assertFalse(result.reachable)
        self.assertEqual(result.classification, "all_targets_unreachable")

    def test_health_result_carries_no_public_ip_field(self) -> None:
        result = probe(successes=2)

        self.assertFalse(hasattr(result, "public_ip"))

if __name__ == "__main__":
    unittest.main()
